use super::{write_archive_reporting, ArchiveEntry, ArchiveExtras, WriterOptions};
use crate::write_stream::CallerOutput;
use crate::{ArchiveReadOptions, ArchiveReader, EntrySource, Error, FeatureSet, WriterResources};
use std::io::Cursor;

const ABOVE: u64 = 256 * 1024;
const PASSWORD: &[u8] = b"secret";

fn text(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|at| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if at % 2 == 0 {
                (state >> 24) as u8
            } else {
                b'a' + (at % 13) as u8
            }
        })
        .collect()
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Encryption {
    headers: bool,
    members: bool,
}

impl Encryption {
    fn headers_only(headers: bool) -> Self {
        Self {
            headers,
            members: false,
        }
    }

    fn password(self) -> Option<&'static [u8]> {
        (self.headers || self.members).then_some(PASSWORD)
    }
}

fn entries(members: &[Vec<u8>], lock: Encryption) -> Vec<ArchiveEntry> {
    members
        .iter()
        .enumerate()
        .map(|(index, data)| {
            let entry = ArchiveEntry::new(
                format!("member{index}.bin").into_bytes(),
                EntrySource::from_bytes(data.clone()),
            )
            .with_mtime(Some(0x5000_0000));
            if lock.members {
                entry.with_password(PASSWORD)
            } else {
                entry
            }
        })
        .collect()
}

fn options(lock: Encryption) -> WriterOptions {
    let mut features = FeatureSet::store_only();
    features.header_encryption = lock.headers;
    WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(1)
}

fn extras(lock: Encryption) -> ArchiveExtras<'static> {
    let mut extras = ArchiveExtras::default();
    if lock.headers {
        extras.header_password = Some(PASSWORD);
    }
    extras
}

fn seekable(
    members: &[Vec<u8>],
    lock: Encryption,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    write_archive_reporting(
        &entries(members, lock),
        options(lock),
        extras(lock),
        resources,
        None,
        CallerOutput::seekable(&mut output).streaming_above(ABOVE),
    )?;
    Ok(output.into_inner())
}

fn streamed(
    members: &[Vec<u8>],
    lock: Encryption,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Vec::new();
    write_archive_reporting(
        &entries(members, lock),
        options(lock),
        extras(lock),
        resources,
        None,
        CallerOutput::stream(&mut output).streaming_above(ABOVE),
    )?;
    Ok(output)
}

fn assert_holds(archive: &[u8], members: &[Vec<u8>], lock: Encryption) {
    let password = lock.password();
    let options = if lock.headers {
        ArchiveReadOptions::with_password(PASSWORD)
    } else {
        ArchiveReadOptions::new()
    };
    let reader = ArchiveReader::read_with_options(archive, options).unwrap();
    reader.test(password).unwrap();
    for (index, data) in members.iter().enumerate() {
        let name = format!("member{index}.bin");
        assert_eq!(
            reader
                .read_member(name.as_bytes(), password)
                .unwrap()
                .as_ref(),
            Some(data),
            "{name}"
        );
    }
}

fn header_encryption_cases() -> Vec<Encryption> {
    if cfg!(feature = "encryption") {
        vec![
            Encryption::headers_only(false),
            Encryption::headers_only(true),
        ]
    } else {
        vec![Encryption::headers_only(false)]
    }
}

#[cfg(feature = "encryption")]
fn member_encryption_cases() -> [Encryption; 2] {
    [false, true].map(|headers| Encryption {
        headers,
        members: true,
    })
}

#[test]
fn a_large_member_is_spooled_only_on_a_stream_output() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)];
    for lock in header_encryption_cases() {
        // Room for the small members, not the large one's packed bytes.
        let resources = WriterResources::default().with_max_spool_bytes(64 * 1024);
        let archive = seekable(&members, lock, &resources).unwrap();
        assert_holds(&archive, &members, lock);

        let error = streamed(&members, lock, &resources).unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
            "{error}"
        );
        let unlimited = streamed(&members, lock, &WriterResources::default());
        assert_holds(&unlimited.unwrap(), &members, lock);
    }
}

#[test]
fn a_large_member_that_does_not_pack_is_stored_over_its_attempt() {
    let large = noise(600 * 1024, 7);
    for members in [
        vec![text(4096, 1), large.clone(), text(4096, 3)],
        vec![text(4096, 1), large.clone()],
    ] {
        for lock in header_encryption_cases() {
            let resources = WriterResources::default();
            let archive = seekable(&members, lock, &resources).unwrap();
            assert_holds(&archive, &members, lock);
            let streamed = streamed(&members, lock, &resources).unwrap();
            // The stored header may carry a padded size; nothing else differs.
            assert!(archive.len() >= streamed.len() && archive.len() <= streamed.len() + 32);
        }
    }
}

#[test]
fn an_in_place_archive_does_not_depend_on_the_thread_count() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), text(300 * 1024, 4)];
    let resources = WriterResources::default();
    let archive = seekable(&members, Encryption::headers_only(false), &resources).unwrap();
    assert_holds(&archive, &members, Encryption::headers_only(false));
    #[cfg(feature = "parallel")]
    for threads in [1, 3] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let again = pool
            .install(|| seekable(&members, Encryption::headers_only(false), &resources))
            .unwrap();
        assert!(again == archive, "{threads} threads wrote another archive");
    }
}

#[test]
fn a_member_packed_smaller_than_its_reserved_size_field_reads_back() {
    // 1 MiB reserves three vint bytes; this packs to well under 16 KiB.
    let repeated: Vec<u8> = b"the same line again\n"
        .iter()
        .copied()
        .cycle()
        .take(1 << 20)
        .collect();
    let members = vec![text(4096, 1), repeated, text(4096, 3)];
    for lock in header_encryption_cases() {
        let resources = WriterResources::default();
        let archive = seekable(&members, lock, &resources).unwrap();
        assert_holds(&archive, &members, lock);
        if !lock.headers {
            let streamed = streamed(&members, lock, &resources).unwrap();
            assert!(archive.len() > streamed.len(), "the size field is padded");
        }
    }
}

#[test]
fn a_large_member_with_a_blake2sp_record_is_patched_and_stored_over() {
    let mut features = FeatureSet::store_only();
    features.blake2sp = true;
    let options =
        WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(1);
    for members in [
        vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)],
        vec![text(4096, 1), noise(600 * 1024, 7)],
    ] {
        let mut output = Cursor::new(Vec::new());
        write_archive_reporting(
            &entries(&members, Encryption::headers_only(false)),
            options,
            ArchiveExtras::default(),
            &WriterResources::default(),
            None,
            CallerOutput::seekable(&mut output).streaming_above(ABOVE),
        )
        .unwrap();
        assert_holds(
            &output.into_inner(),
            &members,
            Encryption::headers_only(false),
        );
    }
}

#[cfg(feature = "encryption")]
#[test]
fn a_large_encrypted_member_is_spooled_only_on_a_stream_output() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)];
    for lock in member_encryption_cases() {
        let resources = WriterResources::default().with_max_spool_bytes(64 * 1024);
        let archive = seekable(&members, lock, &resources).unwrap();
        assert_holds(&archive, &members, lock);

        let error = streamed(&members, lock, &resources).unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
            "{error}"
        );
    }
}

#[cfg(feature = "encryption")]
fn members_as_read(archive: &[u8], lock: Encryption) -> Vec<impl PartialEq + std::fmt::Debug> {
    let password = lock.headers.then_some(PASSWORD);
    let archive = crate::rar50::Archive::parse_with_password(archive, password).unwrap();
    archive
        .files()
        .map(|file| {
            (
                file.name.clone(),
                file.unpacked_size,
                file.compression_info,
                file.data_crc32,
                file.hash.clone(),
                file.encryption.clone(),
                {
                    let packed = file.packed_data(&archive).unwrap();
                    let mut crc = crate::crc32::Crc32::new();
                    crc.update(&packed);
                    (packed.len(), crc.finish())
                },
            )
        })
        .collect()
}

#[cfg(feature = "encryption")]
#[test]
fn seeded_encrypted_outputs_differ_only_in_the_padded_size_field() {
    for members in [
        vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)],
        vec![text(4096, 1), noise(600 * 1024, 7), text(4096, 3)],
        vec![text(4096, 1), noise(600 * 1024, 7)],
    ] {
        for lock in member_encryption_cases() {
            let resources = WriterResources::default();
            let archive =
                crate::entropy::seeded::with(|| seekable(&members, lock, &resources).unwrap());
            assert_holds(&archive, &members, lock);
            let streamed =
                crate::entropy::seeded::with(|| streamed(&members, lock, &resources).unwrap());
            assert_holds(&streamed, &members, lock);
            assert_eq!(
                members_as_read(&archive, lock),
                members_as_read(&streamed, lock)
            );
            assert!(archive.len() >= streamed.len() && archive.len() <= streamed.len() + 32);
            // The main header and the end block draw after the members, so they pin the order too.
            assert_eq!(archive[..64], streamed[..64]);
            assert_eq!(
                archive[archive.len() - 48..],
                streamed[streamed.len() - 48..]
            );
        }
    }
}
