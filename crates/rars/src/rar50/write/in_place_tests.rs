use super::{write_archive_reporting, ArchiveEntry, ArchiveExtras, WriterOptions};
use crate::write_stream::CallerOutput;
use crate::{
    ArchiveReadOptions, ArchiveReader, EntrySource, Error, FeatureSet, FilterKind, FilterPolicy,
    WriterResources,
};
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
    seekable_with(members, lock, extras(lock), resources)
}

fn seekable_with(
    members: &[Vec<u8>],
    lock: Encryption,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    write_archive_reporting(
        &entries(members, lock),
        options(lock),
        extras,
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
    streamed_with(members, lock, extras(lock), resources)
}

fn streamed_with(
    members: &[Vec<u8>],
    lock: Encryption,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Vec::new();
    write_archive_reporting(
        &entries(members, lock),
        options(lock),
        extras,
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

fn quick_open_records(archive: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let parsed = crate::rar50::Archive::parse(archive).unwrap();
    let block_at = crate::detect::RAR50_SIGNATURE.len()
        + parsed.main.locator().unwrap().quick_open_offset.unwrap() as usize;
    let service = parsed
        .services()
        .find(|service| service.name == b"QO")
        .unwrap();
    assert_eq!(
        service.block.offset, block_at,
        "the locator points at the block"
    );
    let payload = &archive[service.block.data_range.clone()];
    let vint = |at: &mut usize| {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = payload[*at];
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        value as usize
    };
    let mut records = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        at += 4;
        let end = vint(&mut at);
        let end = at + end;
        assert_eq!(vint(&mut at), 0);
        let distance = vint(&mut at);
        let len = vint(&mut at);
        records.push((block_at - distance, payload[at..at + len].to_vec()));
        at = end;
    }
    records
}

#[test]
fn quick_open_repeats_every_header_as_finally_written() {
    let members = vec![
        text(4096, 1),
        text(1024 * 1024, 2),
        noise(600 * 1024, 7),
        text(4096, 3),
    ];
    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let options =
        WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(1);
    let write = |output: CallerOutput<'_>| {
        write_archive_reporting(
            &entries(&members, Encryption::headers_only(false)),
            options,
            ArchiveExtras::default(),
            &WriterResources::default(),
            None,
            output.streaming_above(ABOVE),
        )
        .unwrap()
    };
    let mut seekable = Cursor::new(Vec::new());
    write(CallerOutput::seekable(&mut seekable));
    let mut streamed = Vec::new();
    write(CallerOutput::stream(&mut streamed));
    for archive in [seekable.into_inner(), streamed] {
        assert_holds(&archive, &members, Encryption::headers_only(false));
        let parsed = crate::rar50::Archive::parse(&archive).unwrap();
        let headers: Vec<_> = parsed
            .files()
            .map(|file| {
                (
                    file.block.offset,
                    archive[file.block.offset..file.block.header_range.end].to_vec(),
                )
            })
            .collect();
        assert_eq!(headers.len(), members.len());
        assert_eq!(quick_open_records(&archive), headers);
    }
}

#[test]
fn quick_open_after_a_prefix_leaves_the_prefix_alone() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)];
    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let options =
        WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(1);
    let prefix = vec![0x5a; 1000];
    let mut output = Cursor::new(prefix.clone());
    output.set_position(prefix.len() as u64);
    write_archive_reporting(
        &entries(&members, Encryption::headers_only(false)),
        options,
        ArchiveExtras::default(),
        &WriterResources::default(),
        None,
        CallerOutput::seekable(&mut output).streaming_above(ABOVE),
    )
    .unwrap();
    let output = output.into_inner();
    assert_eq!(output[..prefix.len()], prefix);
    let archive = &output[prefix.len()..];
    assert_holds(archive, &members, Encryption::headers_only(false));
    assert_eq!(quick_open_records(archive).len(), members.len());
}

fn filtered(lock: Encryption) -> ArchiveExtras<'static> {
    extras(lock).with_filter_policy(FilterPolicy::explicit(FilterKind::Delta { channels: 4 }))
}

fn every_encryption_case() -> Vec<Encryption> {
    let cases = header_encryption_cases();
    #[cfg(feature = "encryption")]
    let cases: Vec<_> = cases.into_iter().chain(member_encryption_cases()).collect();
    cases
}

#[test]
fn a_large_explicit_filter_member_is_spooled_only_on_a_stream_output() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), text(4096, 3)];
    for lock in every_encryption_case() {
        let resources = WriterResources::default().with_max_spool_bytes(64 * 1024);
        let archive = seekable_with(&members, lock, filtered(lock), &resources).unwrap();
        assert_holds(&archive, &members, lock);

        let error = streamed_with(&members, lock, filtered(lock), &resources).unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
            "{error}"
        );
        let unlimited = streamed_with(&members, lock, filtered(lock), &WriterResources::default());
        assert_holds(&unlimited.unwrap(), &members, lock);
    }
}

fn data_size_width(archive: &[u8], name: &[u8]) -> (usize, u64) {
    let parsed = crate::rar50::Archive::parse(archive).unwrap();
    let file = parsed.files().find(|file| file.name == name).unwrap();
    let vint = |at: usize| {
        archive[at..]
            .iter()
            .position(|byte| byte & 0x80 == 0)
            .unwrap()
            + 1
    };
    // CRC, then the header size, type and flags, then the extra area size.
    let mut at = file.block.offset + 4;
    for _ in 0..3 {
        at += vint(at);
    }
    if file.block.extra_area_size.is_some() {
        at += vint(at);
    }
    (vint(at), file.block.data_size.unwrap())
}

#[test]
fn an_explicit_filter_member_reserves_room_to_outgrow_its_size() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2)];
    let resources = WriterResources::default();
    // 1 MiB takes three vint bytes, and the most it could pack to five.
    let locks = vec![Encryption::headers_only(false)];
    #[cfg(feature = "encryption")]
    let locks: Vec<_> = locks
        .into_iter()
        .chain([Encryption {
            headers: false,
            members: true,
        }])
        .collect();
    for lock in locks {
        let plain = seekable(&members, lock, &resources).unwrap();
        assert_eq!(data_size_width(&plain, b"member1.bin").0, 3);
        let archive = seekable_with(&members, lock, filtered(lock), &resources).unwrap();
        assert_eq!(data_size_width(&archive, b"member1.bin").0, 5);
        assert_holds(&archive, &members, lock);
    }
}

#[test]
fn an_explicit_filter_member_that_outgrows_its_size_goes_out_in_place() {
    let members = vec![text(4096, 1), noise(600 * 1024, 7), text(4096, 3)];
    for lock in every_encryption_case() {
        let resources = WriterResources::default().with_max_spool_bytes(64 * 1024);
        let archive = seekable_with(&members, lock, filtered(lock), &resources).unwrap();
        assert_holds(&archive, &members, lock);
        if !lock.headers {
            let (_, packed) = data_size_width(&archive, b"member1.bin");
            assert!(packed > 600 * 1024, "packed to {packed}");
        }
    }
}

#[test]
fn an_in_place_explicit_filter_archive_does_not_depend_on_the_thread_count() {
    let members = vec![text(4096, 1), text(1024 * 1024, 2), noise(300 * 1024, 4)];
    let lock = Encryption::headers_only(false);
    let resources = WriterResources::default();
    let archive = seekable_with(&members, lock, filtered(lock), &resources).unwrap();
    assert_holds(&archive, &members, lock);
    #[cfg(feature = "parallel")]
    for threads in [1, 3] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let again = pool
            .install(|| seekable_with(&members, lock, filtered(lock), &resources))
            .unwrap();
        assert!(again == archive, "{threads} threads wrote another archive");
    }
}

#[test]
#[cfg(feature = "recovery")]
fn a_record_read_back_covers_headers_patched_in_place() {
    let members = vec![
        text(4096, 1),
        text(1024 * 1024, 2),
        noise(600 * 1024, 7),
        text(4096, 3),
    ];
    for lock in header_encryption_cases() {
        // Quick open is refused with encrypted headers.
        for quick_open in [false, true]
            .into_iter()
            .filter(|&on| !(on && lock.headers))
        {
            let mut options = options(lock);
            options.features.quick_open = quick_open;
            let mut output = Cursor::new(Vec::new());
            write_archive_reporting(
                &entries(&members, lock),
                options,
                extras(lock).with_recovery_percent(Some(5)),
                // Room for the packed windows, not a mirror of the archive.
                &WriterResources::default().with_max_spool_bytes(1024 * 1024),
                None,
                CallerOutput::readable(&mut output).streaming_above(ABOVE),
            )
            .unwrap();
            let archive = output.into_inner();
            assert_holds(&archive, &members, lock);

            let mut damaged = archive.clone();
            // Inside the large compressed member.
            damaged[300 * 1024..300 * 1024 + 64]
                .iter_mut()
                .for_each(|byte| *byte ^= 0xff);
            let read_options = match lock.password() {
                Some(password) => ArchiveReadOptions::with_password(password),
                None => ArchiveReadOptions::new(),
            };
            let repaired =
                crate::rar50::repair_inline_recovery_bytes_with_options(&damaged, read_options)
                    .unwrap();
            assert!(repaired.data == archive, "quick open {quick_open}");
        }
    }
}

fn solid(lock: Encryption) -> WriterOptions {
    let mut options = options(lock);
    options.features.solid = true;
    options
}

fn solid_archive(
    members: &[Vec<u8>],
    lock: Encryption,
    policy: FilterPolicy,
    resources: &WriterResources,
    output: CallerOutput<'_>,
) -> crate::Result<()> {
    solid_archive_with(members, solid(lock), lock, policy, resources, output)
}

fn solid_archive_with(
    members: &[Vec<u8>],
    options: WriterOptions,
    lock: Encryption,
    policy: FilterPolicy,
    resources: &WriterResources,
    output: CallerOutput<'_>,
) -> crate::Result<()> {
    write_archive_reporting(
        &entries(members, lock),
        options,
        extras(lock).with_filter_policy(policy),
        resources,
        None,
        output.streaming_above(ABOVE),
    )
}

fn solid_seekable(
    members: &[Vec<u8>],
    lock: Encryption,
    policy: FilterPolicy,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let output_ref = CallerOutput::seekable(&mut output);
    solid_archive(members, lock, policy, resources, output_ref)?;
    Ok(output.into_inner())
}

fn solid_streamed(
    members: &[Vec<u8>],
    lock: Encryption,
    policy: FilterPolicy,
    resources: &WriterResources,
) -> crate::Result<Vec<u8>> {
    let mut output = Vec::new();
    let output_ref = CallerOutput::stream(&mut output);
    solid_archive(members, lock, policy, resources, output_ref)?;
    Ok(output)
}

// A run is 1 MiB here. A large member's first run is spooled with the runs
// before it, and the rest goes out as it is packed.
const ONE_RUN: u64 = 1536 * 1024;

#[test]
fn a_large_solid_member_is_spooled_only_on_a_stream_output() {
    let members = vec![text(4096, 1), text(3 * 1024 * 1024, 2), text(4096, 3)];
    for lock in every_encryption_case() {
        let resources = WriterResources::default().with_max_spool_bytes(ONE_RUN);
        let archive = solid_seekable(&members, lock, FilterPolicy::None, &resources).unwrap();
        assert_holds(&archive, &members, lock);

        let error = solid_streamed(&members, lock, FilterPolicy::None, &resources).unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
            "{error}"
        );
        let unlimited = solid_streamed(
            &members,
            lock,
            FilterPolicy::None,
            &WriterResources::default(),
        );
        assert_holds(&unlimited.unwrap(), &members, lock);
    }
}

#[test]
fn large_solid_members_anywhere_in_the_chain_extract_from_either_output() {
    let large = || text(3 * 1024 * 1024, 5);
    for members in [
        vec![large(), text(4096, 1), text(4096, 2)],
        vec![text(4096, 1), Vec::new(), large(), text(4096, 2)],
        vec![text(4096, 1), text(4096, 2), large()],
        vec![large(), samples(3 * 1024 * 1024), text(4096, 3)],
    ] {
        let lock = Encryption::headers_only(false);
        // Room for one run of a large member, not all of it.
        let capped = WriterResources::default().with_max_spool_bytes(ONE_RUN);
        let archive = solid_seekable(&members, lock, FilterPolicy::None, &capped).unwrap();
        assert_holds(&archive, &members, lock);
        let resources = WriterResources::default();
        let streamed = solid_streamed(&members, lock, FilterPolicy::None, &resources);
        assert_holds(&streamed.unwrap(), &members, lock);
    }
}

fn samples(len: usize) -> Vec<u8> {
    (0..len / 4)
        .flat_map(|at| {
            let left = ((at as f64 / 40.0).sin() * 12_000.0) as i16;
            let right = ((at as f64 / 55.0).cos() * 9_000.0) as i16;
            [left.to_le_bytes(), right.to_le_bytes()].concat()
        })
        .collect()
}

#[test]
fn an_in_place_solid_archive_does_not_depend_on_the_thread_count() {
    let members = vec![
        text(4096, 1),
        text(1024 * 1024, 2),
        samples(300 * 1024),
        text(4096, 3),
    ];
    let lock = Encryption::headers_only(false);
    let resources = WriterResources::default();
    for policy in [FilterPolicy::None, FilterPolicy::Auto] {
        let archive = solid_seekable(&members, lock, policy.clone(), &resources).unwrap();
        assert_holds(&archive, &members, lock);
        #[cfg(feature = "parallel")]
        for threads in [1, 3] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let again = pool
                .install(|| solid_seekable(&members, lock, policy.clone(), &resources))
                .unwrap();
            assert!(again == archive, "{threads} threads wrote another archive");
        }
    }
}

#[test]
fn solid_outputs_pack_alike_and_differ_only_in_the_padded_size_field() {
    // A run is 1 MiB here, so the 16 KiB member opens one, which a cut before
    // the large member would leave too short to search a tree.
    let source = include_bytes!("compress.rs");
    let mut members: Vec<Vec<u8>> = (0..16).map(|seed| text(64 * 1024, seed)).collect();
    members.push(source[..16 * 1024].to_vec());
    members.push(text(600 * 1024, 20));
    members.push(source[16 * 1024..20 * 1024].to_vec());
    let lock = Encryption::headers_only(false);
    let resources = WriterResources::default();
    let mut options = WriterOptions::new(crate::ArchiveVersion::Rar50, FeatureSet::store_only())
        .with_compression_level(2)
        .with_dictionary_size(128 * 1024);
    options.features.solid = true;
    let mut archive = Cursor::new(Vec::new());
    let output = CallerOutput::seekable(&mut archive);
    let policy = FilterPolicy::None;
    solid_archive_with(&members, options, lock, policy.clone(), &resources, output).unwrap();
    let archive = archive.into_inner();
    let mut streamed = Vec::new();
    let output = CallerOutput::stream(&mut streamed);
    solid_archive_with(&members, options, lock, policy, &resources, output).unwrap();
    assert_holds(&archive, &members, lock);
    assert_eq!(
        members_as_read(&archive, lock),
        members_as_read(&streamed, lock)
    );
    assert!(archive.len() >= streamed.len() && archive.len() <= streamed.len() + 32);
}
