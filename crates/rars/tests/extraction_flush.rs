#![cfg(feature = "write")]

use rars::{
    rar13, rar15_40, rar50, Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder,
    Error, ErrorKind, ExtractionDecision, ExtractionErrorAction, ExtractionOutcome,
    ReadCancellation, Result,
};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const VERSIONS: [ArchiveVersion; 5] = [
    ArchiveVersion::Rar13,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];
const FIRST: &[u8] = b"first";
const SECOND: &[u8] = b"second";

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Write(usize),
    Flush,
    Drop,
}

#[derive(Debug)]
struct MyError;

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("test destination failure")
    }
}

impl std::error::Error for MyError {}

#[derive(Default)]
struct RecordingWriter {
    events: Arc<Mutex<Vec<Event>>>,
    fail_write: bool,
    fail_flush: bool,
    cancel_on_write: Option<ReadCancellation>,
}

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::other(MyError));
        }
        self.events.lock().unwrap().push(Event::Write(bytes.len()));
        if let Some(token) = &self.cancel_on_write {
            token.cancel();
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.events.lock().unwrap().push(Event::Flush);
        if self.fail_flush {
            return Err(io::Error::other(MyError));
        }
        Ok(())
    }
}

impl Drop for RecordingWriter {
    fn drop(&mut self) {
        self.events.lock().unwrap().push(Event::Drop);
    }
}

#[derive(Default)]
struct Recordings(BTreeMap<Vec<u8>, Arc<Mutex<Vec<Event>>>>);

impl Recordings {
    fn writer(&mut self, name: &[u8]) -> RecordingWriter {
        let writer = RecordingWriter::default();
        assert!(
            self.0
                .insert(name.to_vec(), writer.events.clone())
                .is_none(),
            "opened {name:?} twice"
        );
        writer
    }

    fn open(&mut self, name: &[u8]) -> Result<Box<dyn Write>> {
        Ok(Box::new(self.writer(name)))
    }

    fn assert_flushed(&self, name: &[u8], size: usize, case: impl std::fmt::Debug) {
        let events = self.0[name].lock().unwrap();
        let [writes @ .., Event::Flush, Event::Drop] = events.as_slice() else {
            panic!("{case:?}, {name:?}: expected writes, flush, drop, got {events:?}");
        };
        let written: usize = writes
            .iter()
            .map(|event| match event {
                Event::Write(len) => *len,
                event => panic!("{case:?}, {name:?}: unexpected event {event:?}"),
            })
            .sum();
        assert_eq!(written, size, "{case:?}, {name:?}");
    }

    /// `name` got no flush, if it was opened at all.
    fn assert_never_flushed(&self, name: &[u8], case: impl std::fmt::Debug) {
        if let Some(events) = self.0.get(name) {
            let events = events.lock().unwrap();
            assert!(!events.contains(&Event::Flush), "{case:?}: {events:?}");
        }
    }

    fn assert_unflushed(&self, name: &[u8]) {
        let events = self.0[name].lock().unwrap();
        assert_eq!(events.last(), Some(&Event::Drop));
        assert!(!events.contains(&Event::Flush), "{events:?}");
    }
}

fn builder(version: ArchiveVersion, store: bool, solid: bool) -> Builder {
    // Level zero also exercises the legacy builders' solid configuration.
    Builder::new(version)
        .solid(solid)
        .compression_level(store.then_some(0))
}

fn add(builder: &mut Builder, name: &[u8], data: Vec<u8>) {
    builder.add_bytes(name.to_vec(), data, None, None).unwrap();
}

fn fixture(version: ArchiveVersion, store: bool, solid: bool) -> Vec<u8> {
    let mut builder = builder(version, store, solid);
    for name in [FIRST, SECOND] {
        add(&mut builder, name, b"repeated synthetic data\n".repeat(256));
    }
    builder.to_bytes().unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Api {
    Extract,
    Options,
    Parallel,
    ParallelOptions,
    Control,
    ControlAndErrors,
    WithLinks,
    Arriving,
    Volumes,
    VolumeOptions,
    VolumeLinks,
    Family,
    FamilyOptions,
    FamilyParallel,
    FamilyRedirections,
    Rar50Settled,
    FamilyVolumes,
    FamilyVolumeOptions,
}

const SINGLE_APIS: [Api; 18] = [
    Api::Extract,
    Api::Options,
    Api::Parallel,
    Api::ParallelOptions,
    Api::Control,
    Api::ControlAndErrors,
    Api::WithLinks,
    Api::Arriving,
    Api::Volumes,
    Api::VolumeOptions,
    Api::VolumeLinks,
    Api::Family,
    Api::FamilyOptions,
    Api::FamilyParallel,
    Api::FamilyRedirections,
    Api::Rar50Settled,
    Api::FamilyVolumes,
    Api::FamilyVolumeOptions,
];

const VOLUME_APIS: [Api; 6] = [
    Api::Arriving,
    Api::Volumes,
    Api::VolumeOptions,
    Api::VolumeLinks,
    Api::FamilyVolumes,
    Api::FamilyVolumeOptions,
];

impl Api {
    fn extract(self, volumes: &[Archive], recordings: &mut Recordings) -> Result<()> {
        let first = &volumes[0];
        let options = ArchiveReadOptions::new();
        if matches!(self, Self::Control | Self::ControlAndErrors) {
            let decide = |member: &rars::ArchiveMember| {
                if member.meta.is_directory {
                    return Ok(ExtractionDecision::Skip);
                }
                Ok(ExtractionDecision::Extract(
                    recordings.open(&member.meta.name)?,
                ))
            };
            return if matches!(self, Self::Control) {
                first.extract_with_control(options, decide).map(|_| ())
            } else {
                first
                    .extract_with_control_and_errors(options, decide, |_, e| panic!("{e}"))
                    .map(|_| ())
            };
        }
        let open = |meta: &rars::ExtractedEntryMeta| recordings.open(&meta.name);
        match self {
            Self::Extract => first.extract_to(None, open),
            Self::Options => first.extract_to_with_options(options, open),
            Self::Parallel => first.extract_to_parallel_buffered(None, open),
            Self::ParallelOptions => first.extract_to_parallel_buffered_with_options(options, open),
            Self::Control | Self::ControlAndErrors => unreachable!(),
            Self::WithLinks => first.extract_with_links(options, open, |_, _| panic!("link")),
            Self::Arriving => {
                first.extract_with_volumes(volumes[1..].iter().cloned().map(Ok), options, open)
            }
            Self::Volumes => rars::extract_volumes_to(volumes, None, open),
            Self::VolumeOptions => rars::extract_volumes_to_with_options(volumes, options, open),
            Self::VolumeLinks => {
                rars::extract_volumes_with_links(volumes, options, open, |_, _| panic!("link"))
            }
            _ => self.extract_family(volumes, options, recordings),
        }
    }

    fn extract_family(
        self,
        volumes: &[Archive],
        options: ArchiveReadOptions<'_>,
        recordings: &mut Recordings,
    ) -> Result<()> {
        match &volumes[0] {
            Archive::Rar13(first) => {
                let open = |meta: &rar13::ExtractedEntryMeta| recordings.open(&meta.name);
                match self {
                    Self::Family => first.extract_to(None, open),
                    Self::FamilyOptions => first.extract_to_with_options(options, open),
                    Self::FamilyVolumes | Self::FamilyVolumeOptions => {
                        let volumes = family_volumes(volumes, |archive| match archive {
                            Archive::Rar13(inner) => inner,
                            _ => unreachable!(),
                        });
                        if matches!(self, Self::FamilyVolumes) {
                            rar13::extract_volumes_to(&volumes, None, open)
                        } else {
                            rar13::extract_volumes_to_with_options(&volumes, options, open)
                        }
                    }
                    _ => Ok(()),
                }
            }
            Archive::Rar15To40(first) => {
                let open = |meta: &rar15_40::ExtractedEntryMeta| recordings.open(&meta.name);
                match self {
                    Self::Family => first.extract_to(options, open),
                    Self::FamilyParallel => first.extract_to_parallel_buffered(options, open),
                    Self::FamilyVolumes => {
                        let volumes = family_volumes(volumes, |archive| match archive {
                            Archive::Rar15To40(inner) => inner,
                            _ => unreachable!(),
                        });
                        rar15_40::extract_volumes_to(&volumes, options, open)
                    }
                    _ => Ok(()),
                }
            }
            Archive::Rar50Plus(first) => {
                let open = |meta: &rar50::ExtractedEntryMeta| recordings.open(&meta.name);
                match self {
                    Self::Family => first.extract_to(options, open),
                    Self::FamilyParallel => first.extract_to_parallel_buffered(options, open),
                    Self::FamilyRedirections => {
                        first.extract_to_with_redirections(options, open, |_, _| panic!("link"))
                    }
                    Self::Rar50Settled => rars::output_links::extract_rar50_settled_with_links(
                        first,
                        options.with_threads(2),
                        |meta| Ok(Box::new(recordings.writer(&meta.name))),
                        |_, _| panic!("link"),
                        |_, verified| {
                            assert!(verified);
                            Ok(())
                        },
                    ),
                    Self::FamilyVolumes | Self::FamilyVolumeOptions => {
                        let volumes = family_volumes(volumes, |archive| match archive {
                            Archive::Rar50Plus(inner) => inner,
                            _ => unreachable!(),
                        });
                        if matches!(self, Self::FamilyVolumes) {
                            rar50::extract_volumes_to(&volumes, options, open)
                        } else {
                            rar50::extract_volumes_to_with_redirections(
                                &volumes,
                                options,
                                open,
                                |_, _| panic!("link"),
                            )
                        }
                    }
                    _ => Ok(()),
                }
            }
            _ => unreachable!(),
        }
    }

    fn applies(self, version: ArchiveVersion) -> bool {
        match self {
            Self::FamilyOptions => version == ArchiveVersion::Rar13,
            Self::FamilyParallel => version != ArchiveVersion::Rar13,
            Self::FamilyRedirections | Self::Rar50Settled => version == ArchiveVersion::Rar50,
            Self::FamilyVolumeOptions => {
                matches!(version, ArchiveVersion::Rar13 | ArchiveVersion::Rar50)
            }
            _ => true,
        }
    }
}

fn family_volumes<T: Clone>(volumes: &[Archive], family: impl Fn(&Archive) -> &T) -> Vec<T> {
    volumes
        .iter()
        .map(|archive| family(archive).clone())
        .collect()
}

#[test]
fn every_extractor_flushes_each_file_once_after_all_writes() {
    for version in VERSIONS {
        for (store, solid) in [(true, false), (false, false), (false, true), (true, true)] {
            if version == ArchiveVersion::Rar13 && store && solid {
                continue;
            }
            let archive = ArchiveReader::read_owned(fixture(version, store, solid)).unwrap();
            let volumes = std::slice::from_ref(&archive);
            let members: Vec<_> = archive.members().collect();
            assert_eq!(members.len(), 2);
            for member in &members {
                assert_eq!(member.meta.is_stored, store, "{version:?} {store} {solid}");
            }
            for api in SINGLE_APIS.into_iter().filter(|api| api.applies(version)) {
                let case = (version, store, solid, api);
                let mut recordings = Recordings::default();
                api.extract(volumes, &mut recordings)
                    .unwrap_or_else(|e| panic!("{case:?}: {e}"));
                for member in &members {
                    recordings.assert_flushed(
                        &member.meta.name,
                        member.meta.unpacked_size as usize,
                        case,
                    );
                }
            }
        }
    }
}

#[test]
fn read_options_keep_one_flush_after_all_writes() {
    let variants = [
        ("one thread", ArchiveReadOptions::new().with_threads(1)),
        ("two threads", ArchiveReadOptions::new().with_threads(2)),
        ("four threads", ArchiveReadOptions::new().with_threads(4)),
        (
            "streamed",
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
        ),
        (
            "workspace limit",
            ArchiveReadOptions::new().with_max_reader_workspace_bytes(64 << 20),
        ),
        (
            "member limit",
            ArchiveReadOptions::new().with_max_member_output_bytes(1 << 20),
        ),
        (
            "total limit",
            ArchiveReadOptions::new().with_max_total_output_bytes(1 << 20),
        ),
    ];
    for version in VERSIONS {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let archive = ArchiveReader::read_owned(fixture(version, store, solid)).unwrap();
            for (label, options) in variants {
                for parallel in [false, true] {
                    let case = (version, store, solid, label, parallel);
                    let mut recordings = Recordings::default();
                    let open = |meta: &rars::ExtractedEntryMeta| recordings.open(&meta.name);
                    if parallel {
                        archive.extract_to_parallel_buffered_with_options(options, open)
                    } else {
                        archive.extract_to_with_options(options, open)
                    }
                    .unwrap_or_else(|e| panic!("{case:?}: {e}"));
                    for member in archive.members() {
                        recordings.assert_flushed(
                            &member.meta.name,
                            member.meta.unpacked_size as usize,
                            case,
                        );
                    }
                }
            }
        }
    }
}

fn noise(len: usize, mut state: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn split_set(version: ArchiveVersion, store: bool) -> (Vec<Archive>, usize) {
    let data = noise(30_000, 365);
    let len = data.len();
    let mut builder = builder(version, store, false).volume_size(Some(4096));
    add(&mut builder, FIRST, data);
    let volumes: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 2);
    assert!(volumes[0].members().next().unwrap().meta.is_split_after);
    assert!(
        volumes
            .last()
            .unwrap()
            .members()
            .next()
            .unwrap()
            .meta
            .is_split_before
    );
    (volumes, len)
}

#[test]
fn split_members_flush_only_after_the_last_fragment() {
    for version in VERSIONS {
        for store in [true, false] {
            let (volumes, len) = split_set(version, store);
            for api in VOLUME_APIS.into_iter().filter(|api| api.applies(version)) {
                let case = (version, store, api);
                let mut recordings = Recordings::default();
                api.extract(&volumes, &mut recordings)
                    .unwrap_or_else(|e| panic!("{case:?}: {e}"));
                recordings.assert_flushed(FIRST, len, case);
            }
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let handler = |member: &rars::ArchiveMember, error: &Error| {
                assert_eq!(member.meta.name, FIRST);
                assert_eq!(error.entry_context().unwrap().0, FIRST);
                assert_my_error(error);
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(ExtractionErrorAction::Continue)
            };
            let mut recordings = Recordings::default();
            volumes[0]
                .extract_with_volumes(
                    volumes[1..].iter().cloned().map(Ok),
                    ArchiveReadOptions::new().with_member_error_handler(&handler),
                    |meta| {
                        let mut writer = recordings.writer(&meta.name);
                        writer.fail_flush = true;
                        Ok(Box::new(writer))
                    },
                )
                .unwrap();
            assert_eq!(calls.into_inner(), 1);
            recordings.assert_flushed(FIRST, len, (version, store));
        }
    }
}

#[test]
fn parallel_buffered_flushes_at_each_thread_count() {
    for threads in [1, 2, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| {
            for version in VERSIONS {
                for many in [false, true] {
                    let bytes = if many {
                        many_members(version)
                    } else {
                        fixture(version, false, false)
                    };
                    let archive = ArchiveReader::read_owned(bytes).unwrap();
                    let mut recordings = Recordings::default();
                    Api::Parallel
                        .extract(std::slice::from_ref(&archive), &mut recordings)
                        .unwrap();
                    for member in archive.members() {
                        recordings.assert_flushed(
                            &member.meta.name,
                            member.meta.unpacked_size as usize,
                            (threads, version, many),
                        );
                    }
                }
            }
        });
    }
}

/// Enough members of varied size that parallel extraction has many in flight.
fn many_members(version: ArchiveVersion) -> Vec<u8> {
    let mut builder = builder(version, false, false);
    for index in 0..40u32 {
        let name = format!("m{index:02}").into_bytes();
        add(
            &mut builder,
            &name,
            noise(100 + index as usize * 397, index + 1),
        );
    }
    builder.to_bytes().unwrap()
}

fn damaged_stored_archive(version: ArchiveVersion, hash: bool) -> Archive {
    let bytes = if hash {
        let mut builder = builder(version, true, false).blake2sp(true);
        for name in [FIRST, SECOND] {
            add(&mut builder, name, vec![b'x'; 1024]);
        }
        builder.to_bytes().unwrap()
    } else {
        fixture(version, true, false)
    };
    let archive = ArchiveReader::read(&bytes).unwrap();
    let offset = match archive {
        Archive::Rar13(inner) => inner.entries[0].packed_range.start,
        Archive::Rar15To40(inner) => inner.files().next().unwrap().packed_range.start,
        Archive::Rar50Plus(inner) => inner.files().next().unwrap().block.data_range.start,
        _ => unreachable!(),
    };
    let mut bytes = bytes;
    bytes[offset] ^= 0x80;
    ArchiveReader::read_owned(bytes).unwrap()
}

#[test]
fn bad_checksum_never_flushes_even_when_bytes_are_salvaged() {
    for (version, hash) in VERSIONS
        .into_iter()
        .map(|version| (version, false))
        .chain([(ArchiveVersion::Rar50, true)])
    {
        let archive = damaged_stored_archive(version, hash);
        for salvage in [false, true] {
            let options = ArchiveReadOptions::new().with_salvage(salvage);
            let mut recordings = Recordings::default();
            let error = archive
                .extract_to_with_options(options, |meta| recordings.open(&meta.name))
                .unwrap_err();
            assert_checksum_error(&error, hash);
            recordings.assert_unflushed(FIRST);
            assert!(recordings.0[FIRST]
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::Write(n) if *n > 0)));

            let mut recordings = Recordings::default();
            let mut failures = 0;
            let result = archive
                .extract_with_control_and_errors(
                    options,
                    |member| {
                        Ok(ExtractionDecision::Extract(
                            recordings.open(&member.meta.name)?,
                        ))
                    },
                    |member, error| {
                        assert_eq!(member.meta.name, FIRST);
                        assert_checksum_error(error, hash);
                        failures += 1;
                        Ok(ExtractionErrorAction::Continue)
                    },
                )
                .unwrap();
            assert_eq!(result, ExtractionOutcome::Complete);
            assert_eq!(failures, 1);
            recordings.assert_unflushed(FIRST);
            let len = archive.members().nth(1).unwrap().meta.unpacked_size as usize;
            recordings.assert_flushed(SECOND, len, (version, hash, salvage));

            let mut recordings = Recordings::default();
            let failures = std::sync::atomic::AtomicUsize::new(0);
            let handler = |member: &rars::ArchiveMember, error: &Error| {
                assert_eq!(member.meta.name, FIRST);
                assert_checksum_error(error, hash);
                failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(ExtractionErrorAction::Continue)
            };
            archive
                .extract_to_parallel_buffered_with_options(
                    options.with_member_error_handler(&handler),
                    |meta| recordings.open(&meta.name),
                )
                .unwrap();
            assert_eq!(failures.into_inner(), 1);
            recordings.assert_never_flushed(FIRST, (version, hash, salvage));
            recordings.assert_flushed(SECOND, len, (version, hash, salvage));
        }
    }
}

fn assert_checksum_error(error: &Error, hash: bool) {
    match error.root_cause() {
        Error::HashMismatch { .. } if hash => {}
        Error::CrcMismatch { .. } | Error::Crc32Mismatch { .. } if !hash => {}
        _ => panic!("{error:?}"),
    }
    assert_eq!(error.entry_context().unwrap().0, FIRST);
}

fn assert_my_error(error: &Error) {
    assert!(matches!(error.root_cause(), Error::Io(_)), "{error:?}");
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if let Some(original) = source.downcast_ref::<io::Error>() {
            assert!(original
                .get_ref()
                .unwrap()
                .downcast_ref::<MyError>()
                .is_some());
            return;
        }
        source = source
            .source()
            .unwrap_or_else(|| panic!("missing original I/O error: {error:?}"));
    }
}

/// A 4 KiB first member with no long repeats, then a short second one.
fn uneven_fixture(version: ArchiveVersion, store: bool) -> Vec<u8> {
    let mut builder = builder(version, store, false);
    let letters = noise(4096, 77)
        .into_iter()
        .map(|b| b"abcdefg "[usize::from(b % 8)])
        .collect();
    add(&mut builder, FIRST, letters);
    add(&mut builder, SECOND, b"after the failure".to_vec());
    builder.to_bytes().unwrap()
}

/// Extracts sequentially and in parallel with a handler that carries on, and
/// checks that only `FIRST` failed and was never flushed.
fn assert_only_first_fails_unflushed(
    archive: &Archive,
    options: ArchiveReadOptions<'_>,
    case: impl std::fmt::Debug + Copy + Sync,
) {
    for parallel in [false, true] {
        let failures = std::sync::atomic::AtomicUsize::new(0);
        let handler = |member: &rars::ArchiveMember, _: &Error| {
            assert_eq!(member.meta.name, FIRST, "{case:?}");
            failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(ExtractionErrorAction::Continue)
        };
        let options = options.with_member_error_handler(&handler);
        let mut recordings = Recordings::default();
        let open = |meta: &rars::ExtractedEntryMeta| recordings.open(&meta.name);
        if parallel {
            archive.extract_to_parallel_buffered_with_options(options, open)
        } else {
            archive.extract_to_with_options(options, open)
        }
        .unwrap_or_else(|e| panic!("{case:?} parallel={parallel}: {e}"));
        assert_eq!(failures.into_inner(), 1, "{case:?} parallel={parallel}");
        recordings.assert_never_flushed(FIRST, (case, parallel));
        recordings.assert_flushed(SECOND, 17, (case, parallel));
    }
}

#[test]
fn a_member_that_outgrows_its_declared_size_mid_write_is_never_flushed() {
    // RAR 1.3 copies stored data even when the declared size is smaller, so
    // the writer is opened and the limit trips while writing.
    let mut archive =
        ArchiveReader::read_owned(uneven_fixture(ArchiveVersion::Rar13, true)).unwrap();
    let Archive::Rar13(inner) = &mut archive else {
        unreachable!()
    };
    inner.entries[0].header.unp_size = 500;
    let options = ArchiveReadOptions::new().with_max_member_output_bytes(1000);
    let mut recordings = Recordings::default();
    let error = archive
        .extract_to_with_options(options, |meta| recordings.open(&meta.name))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceLimit, "{error:?}");
    assert!(recordings.0.contains_key(FIRST));
    recordings.assert_unflushed(FIRST);
}

#[test]
fn damaged_compressed_data_is_never_flushed() {
    for version in VERSIONS {
        let mut bytes = uneven_fixture(version, false);
        let range = match ArchiveReader::read(&bytes).unwrap() {
            Archive::Rar13(inner) => inner.entries[0].packed_range.clone(),
            Archive::Rar15To40(inner) => inner.files().next().unwrap().packed_range.clone(),
            Archive::Rar50Plus(inner) => inner.files().next().unwrap().block.data_range.clone(),
            _ => unreachable!(),
        };
        for at in [range.start + 1, range.start + range.len() / 2] {
            bytes[at] ^= 0x5a;
        }
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        assert!(!archive.members().next().unwrap().meta.is_stored);
        assert_only_first_fails_unflushed(&archive, ArchiveReadOptions::new(), version);
    }
}

#[test]
fn a_member_without_a_checksum_is_flushed_after_all_its_data() {
    for (store, solid) in [(true, false), (false, false), (false, true)] {
        let mut archive =
            ArchiveReader::read_owned(fixture(ArchiveVersion::Rar50, store, solid)).unwrap();
        let Archive::Rar50Plus(inner) = &mut archive else {
            unreachable!()
        };
        for block in &mut inner.blocks {
            if let rar50::Block::File(file) = block {
                file.hash = None;
                file.data_crc32 = None;
            }
        }
        for api in [Api::Options, Api::ParallelOptions, Api::Rar50Settled] {
            let case = (store, solid, api);
            let mut recordings = Recordings::default();
            api.extract(std::slice::from_ref(&archive), &mut recordings)
                .unwrap_or_else(|e| panic!("{case:?}: {e}"));
            for member in archive.members() {
                recordings.assert_flushed(
                    &member.meta.name,
                    member.meta.unpacked_size as usize,
                    case,
                );
            }
        }
    }
}

#[test]
fn flush_errors_fail_the_member_and_reach_both_error_handlers() {
    for version in VERSIONS {
        let archive = ArchiveReader::read_owned(fixture(version, false, false)).unwrap();
        let make_writer = |recordings: &mut Recordings, name: &[u8]| -> Box<dyn Write> {
            let mut writer = recordings.writer(name);
            writer.fail_flush = name == FIRST;
            Box::new(writer)
        };
        let check_error = |error: &Error| {
            assert_eq!(error.entry_context().unwrap().0, FIRST);
            assert_my_error(error);
        };
        let options = ArchiveReadOptions::new();
        let mut recordings = Recordings::default();
        let error = archive
            .extract_to(None, |meta| Ok(make_writer(&mut recordings, &meta.name)))
            .unwrap_err();
        check_error(&error);
        let len = archive.members().next().unwrap().meta.unpacked_size as usize;
        recordings.assert_flushed(FIRST, len, version);
        assert!(!recordings.0.contains_key(SECOND));

        let handler = |member: &rars::ArchiveMember, error: &Error| {
            assert_eq!(member.meta.name, FIRST);
            check_error(error);
            Ok(ExtractionErrorAction::Continue)
        };
        for mode in [Api::ControlAndErrors, Api::ParallelOptions, Api::Arriving] {
            let mut recordings = Recordings::default();
            let options = options.with_member_error_handler(&handler);
            match mode {
                Api::ControlAndErrors => {
                    assert_eq!(
                        archive
                            .extract_with_control_and_errors(
                                options,
                                |member| Ok(ExtractionDecision::Extract(make_writer(
                                    &mut recordings,
                                    &member.meta.name
                                ))),
                                handler,
                            )
                            .unwrap(),
                        ExtractionOutcome::Complete
                    );
                }
                Api::ParallelOptions => archive
                    .extract_to_parallel_buffered_with_options(options, |meta| {
                        Ok(make_writer(&mut recordings, &meta.name))
                    })
                    .unwrap(),
                Api::Arriving => archive
                    .extract_with_volumes([], options, |meta| {
                        Ok(make_writer(&mut recordings, &meta.name))
                    })
                    .unwrap(),
                _ => unreachable!(),
            }
            for name in [FIRST, SECOND] {
                recordings.assert_flushed(name, len, (version, mode));
            }
        }
    }
}

#[test]
fn directories_and_links_have_no_output_to_flush() {
    for version in VERSIONS {
        let mut builder = builder(version, true, false);
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        add(&mut builder, FIRST, vec![b'x']);
        let has_links = !matches!(version, ArchiveVersion::Rar13 | ArchiveVersion::Rar15);
        if has_links {
            builder
                .add_unix_symlink(b"link".to_vec(), FIRST.to_vec(), false, None, None)
                .unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        for volumes in [false, true] {
            let mut recordings = Recordings::default();
            let open = |meta: &rars::ExtractedEntryMeta| {
                assert_ne!(meta.name, b"link");
                recordings.open(&meta.name)
            };
            let mut links = 0;
            let link = |meta: &rars::ExtractedEntryMeta, target: rars::ExtractedLink<'_>| {
                links += 1;
                assert_eq!(meta.name, b"link");
                assert_eq!(target.target(), FIRST);
                Ok(())
            };
            let options = ArchiveReadOptions::new();
            if volumes {
                rars::extract_volumes_with_links(
                    std::slice::from_ref(&archive),
                    options,
                    open,
                    link,
                )
                .unwrap();
            } else {
                archive.extract_with_links(options, open, link).unwrap();
            }
            assert_eq!(links, usize::from(has_links));
            // Directory notifications still reach the callback. Its placeholder
            // writer must be dropped without any writes or flushes.
            let directory = archive
                .members()
                .find(|member| member.meta.is_directory)
                .unwrap();
            assert_eq!(
                *recordings.0[&directory.meta.name].lock().unwrap(),
                [Event::Drop]
            );
            recordings.assert_flushed(FIRST, 1, (version, volumes));
        }
    }
}

#[test]
fn solid_skip_and_cancellation_leave_only_successful_members_flushed() {
    for version in VERSIONS {
        let archive = ArchiveReader::read_owned(fixture(version, false, true)).unwrap();
        let mut recordings = Recordings::default();
        let options = ArchiveReadOptions::new().with_solid_skip_budget(u64::MAX);
        archive
            .extract_with_control(options, |member| {
                if member.meta.name == FIRST {
                    Ok(ExtractionDecision::Skip)
                } else {
                    Ok(ExtractionDecision::Extract(
                        recordings.open(&member.meta.name)?,
                    ))
                }
            })
            .unwrap();
        assert!(!recordings.0.contains_key(FIRST));
        let len = archive.members().nth(1).unwrap().meta.unpacked_size as usize;
        recordings.assert_flushed(SECOND, len, version);

        let token = ReadCancellation::new();
        let mut recordings = Recordings::default();
        let error = archive
            .extract_to_with_options(
                ArchiveReadOptions::new().with_cancellation(&token),
                |meta| {
                    let mut writer = recordings.writer(&meta.name);
                    writer.cancel_on_write = Some(token.clone());
                    Ok(Box::new(writer))
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        recordings.assert_unflushed(FIRST);
    }
}

#[test]
fn caller_error_survives_entry_and_volume_wrappers() {
    for version in VERSIONS {
        let archive = ArchiveReader::read_owned(fixture(version, false, false)).unwrap();
        let options = ArchiveReadOptions::new();
        let error = archive
            .extract_with_control(options, |_| Err(io::Error::other(MyError).into()))
            .unwrap_err();
        assert!(matches!(error, Error::AtEntry { .. }));
        assert_my_error(&error);

        let mut recordings = Recordings::default();
        let error = archive
            .extract_with_volumes([], options, |meta| {
                let mut writer = recordings.writer(&meta.name);
                writer.fail_write = true;
                Ok(Box::new(writer))
            })
            .unwrap_err();
        assert!(matches!(error, Error::InVolume { index: 0, .. }));
        assert_eq!(error.entry_context().unwrap().0, FIRST);
        assert_my_error(&error);
        recordings.assert_unflushed(FIRST);
    }
}
