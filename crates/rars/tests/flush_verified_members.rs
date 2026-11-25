#![cfg(feature = "write")]
//! Each member's writer is flushed exactly once, after the member's data has
//! been written and has passed its checksum, so a flush means the member is
//! complete and verified. Every archive here is written by rars.

use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ErrorKind, ExtractedEntryMeta, ExtractionDecision, ExtractionErrorAction,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const VERSIONS: [ArchiveVersion; 7] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
];

/// The versions whose builder writes Unix symbolic links.
fn writes_links(version: ArchiveVersion) -> bool {
    !matches!(version, ArchiveVersion::Rar14 | ArchiveVersion::Rar15)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Event {
    Wrote(usize),
    Flushed,
}

/// What a writer does wrong, to the member it is opened for.
#[derive(Clone, Copy)]
enum Fault {
    /// Its flush fails with the caller's own error.
    Flush,
    /// Its writes fail with the caller's own error.
    Write,
    /// The callback opening it fails with the caller's own error.
    Open,
}

/// Each writer's events, in order, with the name of its member.
type Events = Arc<Mutex<Vec<(Vec<u8>, Event)>>>;

/// Everything the writers opened by one extraction saw, by member name.
#[derive(Clone, Default)]
struct Log {
    opened: Arc<Mutex<Vec<Vec<u8>>>>,
    events: Events,
    handled: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct Recorder {
    name: Vec<u8>,
    events: Events,
    fault: Option<Fault>,
}

impl Write for Recorder {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if matches!(self.fault, Some(Fault::Write)) {
            return Err(io::Error::other(MyError));
        }
        let mut events = self.events.lock().unwrap();
        events.push((self.name.clone(), Event::Wrote(bytes.len())));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut events = self.events.lock().unwrap();
        events.push((self.name.clone(), Event::Flushed));
        match self.fault {
            Some(Fault::Flush) => Err(io::Error::other(MyError)),
            _ => Ok(()),
        }
    }
}

impl Log {
    fn writer(&self, name: &[u8], fault: Option<Fault>) -> rars::Result<Box<dyn Write>> {
        self.opened.lock().unwrap().push(name.to_vec());
        if matches!(fault, Some(Fault::Open)) {
            return Err(io::Error::other(MyError).into());
        }
        Ok(Box::new(Recorder {
            name: name.to_vec(),
            events: Arc::clone(&self.events),
            fault,
        }))
    }

    fn open(&self) -> impl FnMut(&ExtractedEntryMeta) -> rars::Result<Box<dyn Write>> + '_ {
        self.open_faulty(b"", None)
    }

    /// Opens writers, the one for `name` with `fault`.
    fn open_faulty<'a>(
        &'a self,
        name: &'a [u8],
        fault: Option<Fault>,
    ) -> impl FnMut(&ExtractedEntryMeta) -> rars::Result<Box<dyn Write>> + 'a {
        move |meta| self.writer(&meta.name, fault.filter(|_| meta.name == name))
    }

    fn handle(&self, member: &ArchiveMember, _: &Error) -> rars::Result<ExtractionErrorAction> {
        self.handled.lock().unwrap().push(member.meta.name.clone());
        Ok(ExtractionErrorAction::Continue)
    }

    fn opened(&self) -> Vec<Vec<u8>> {
        self.opened.lock().unwrap().clone()
    }

    fn handled(&self) -> Vec<Vec<u8>> {
        self.handled.lock().unwrap().clone()
    }

    fn flushes(&self, name: &[u8]) -> usize {
        self.events_for(name)
            .iter()
            .filter(|event| **event == Event::Flushed)
            .count()
    }

    fn written(&self, name: &[u8]) -> usize {
        self.events_for(name)
            .iter()
            .map(|event| match event {
                Event::Wrote(len) => *len,
                Event::Flushed => 0,
            })
            .sum()
    }

    fn events_for(&self, name: &[u8]) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, _)| seen == name)
            .map(|(_, event)| *event)
            .collect()
    }

    /// `name` was flushed exactly once, after all `len` of its bytes.
    fn assert_flushed_once_after(&self, name: &[u8], len: usize, case: &str) {
        let events = self.events_for(name);
        assert_eq!(self.flushes(name), 1, "{case}: {name:?} {events:?}");
        assert_eq!(events.last(), Some(&Event::Flushed), "{case}: {name:?}");
        assert_eq!(self.written(name), len, "{case}: {name:?}");
    }

    fn assert_not_flushed(&self, name: &[u8], case: &str) {
        assert_eq!(self.flushes(name), 0, "{case}: {name:?}");
    }
}

#[derive(Debug)]
struct MyError;

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the caller's own error")
    }
}

impl std::error::Error for MyError {}

/// Pseudo-random bytes, so compressed members stay large enough to split.
fn noise(len: usize, mut seed: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect()
}

fn files() -> Vec<(&'static [u8], Vec<u8>)> {
    vec![
        (b"dir/text", b"flushed once it is verified ".repeat(200)),
        (b"empty", Vec::new()),
        (b"noise", noise(9000, 0x2468_ace1)),
    ]
}

/// A directory, the members of [`files`] and, where the format has them, a
/// symbolic link.
fn builder(version: ArchiveVersion, store: bool, solid: bool, link: bool) -> Builder {
    let mut builder = Builder::new(version).store(store).solid(solid);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    for (name, data) in files() {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
        if link && name == b"dir/text" {
            builder
                .add_unix_symlink(b"link".to_vec(), b"dir/text".to_vec(), false, None, None)
                .unwrap();
        }
    }
    builder
}

fn archive(version: ArchiveVersion, store: bool, solid: bool) -> Archive {
    let builder = builder(version, store, solid, writes_links(version));
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

fn volumes(builder: Builder) -> Vec<Archive> {
    let parts = builder.volume_size(Some(2048)).build_volumes(None).unwrap();
    assert!(parts.len() > 1);
    parts
        .into_iter()
        .map(|part| ArchiveReader::read_owned(part).unwrap())
        .collect()
}

fn assert_files_flushed_once(log: &Log, case: &str) {
    for (name, data) in files() {
        log.assert_flushed_once_after(name, data.len(), case);
    }
    // Directories get no data and no flush; links get no writer at all.
    log.assert_not_flushed(b"dir", case);
    assert_eq!(log.written(b"dir"), 0, "{case}");
    assert!(!log.opened().contains(&b"link".to_vec()), "{case}");
}

fn option_variants() -> Vec<(&'static str, ArchiveReadOptions<'static>)> {
    vec![
        ("default", ArchiveReadOptions::new()),
        ("one thread", ArchiveReadOptions::new().with_threads(1)),
        ("two threads", ArchiveReadOptions::new().with_threads(2)),
        ("four threads", ArchiveReadOptions::new().with_threads(4)),
        (
            "streamed",
            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
        ),
        (
            "workspace limit",
            ArchiveReadOptions::new().with_max_reader_workspace_bytes(64 * 1024 * 1024),
        ),
        (
            "total limit",
            ArchiveReadOptions::new().with_max_total_output_bytes(1 << 20),
        ),
    ]
}

#[test]
fn every_writer_api_flushes_each_file_once_after_its_verified_data() {
    for version in VERSIONS {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let archive = archive(version, store, solid);
            for (label, options) in option_variants() {
                let case = format!("{version:?} store={store} solid={solid} {label}");
                let run = |api: &str, extract: &dyn Fn(&Log) -> rars::Result<()>| {
                    let log = Log::default();
                    extract(&log).unwrap_or_else(|error| panic!("{case} {api}: {error}"));
                    assert_files_flushed_once(&log, &format!("{case} {api}"));
                };
                run("extract_to_with_options", &|log| {
                    archive.extract_to_with_options(options, log.open())
                });
                run("extract_to_parallel_buffered_with_options", &|log| {
                    archive.extract_to_parallel_buffered_with_options(options, log.open())
                });
                run("extract_with_links", &|log| {
                    archive.extract_with_links(options, log.open(), |_, _| Ok(()))
                });
                run("extract_volumes_to_with_options", &|log| {
                    rars::extract_volumes_to_with_options(
                        std::slice::from_ref(&archive),
                        options,
                        log.open(),
                    )
                });
                run("extract_with_control", &|log| {
                    archive
                        .extract_with_control(options, |member| {
                            if member.meta.is_redirection {
                                return Ok(ExtractionDecision::Skip);
                            }
                            // Controlled extraction offers a RAR 1.5-4 link as
                            // a member; leave it out, as the writer-only APIs do.
                            if member.meta.name == b"link" {
                                return Ok(ExtractionDecision::Extract(Box::new(io::sink())));
                            }
                            log.writer(&member.meta.name, None)
                                .map(ExtractionDecision::Extract)
                        })
                        .map(drop)
                });
            }
        }
    }
}

#[test]
fn volume_sets_flush_each_file_once_after_its_last_part() {
    for version in VERSIONS {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            // The legacy volume writer takes one member, and no directory.
            let (set, members) = if version == ArchiveVersion::Rar50 {
                (volumes(builder(version, store, solid, false)), files())
            } else {
                let mut builder = Builder::new(version).store(store).solid(solid);
                let data = noise(9000, 5);
                builder
                    .add_bytes(b"noise".to_vec(), data.clone(), None, None)
                    .unwrap();
                (volumes(builder), vec![(b"noise".as_slice(), data)])
            };
            let case = format!("{version:?} store={store} solid={solid}");
            let run = |api: &str, extract: &dyn Fn(&Log) -> rars::Result<()>| {
                let log = Log::default();
                extract(&log).unwrap_or_else(|error| panic!("{case} {api}: {error}"));
                for (name, data) in &members {
                    log.assert_flushed_once_after(name, data.len(), &format!("{case} {api}"));
                }
                log.assert_not_flushed(b"dir", &case);
            };
            run("extract_volumes_to", &|log| {
                rars::extract_volumes_to(&set, None, log.open())
            });
            run("extract_with_volumes", &|log| {
                set[0].extract_with_volumes(
                    set[1..].iter().cloned().map(Ok),
                    ArchiveReadOptions::new(),
                    log.open(),
                )
            });
            run("extract_volumes_with_links", &|log| {
                rars::extract_volumes_with_links(
                    &set,
                    ArchiveReadOptions::new(),
                    log.open(),
                    |_, _| Ok(()),
                )
            });
        }
    }
}

#[test]
fn parallel_extraction_flushes_many_members_once_each() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        for store in [true, false] {
            let mut builder = Builder::new(version).store(store);
            let members: Vec<_> = (0..40u32)
                .map(|index| {
                    let len = 100 + index as usize * 397;
                    (format!("m{index:02}").into_bytes(), noise(len, index + 1))
                })
                .collect();
            for (name, data) in &members {
                builder
                    .add_bytes(name.clone(), data.clone(), None, None)
                    .unwrap();
            }
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            for (label, options) in option_variants() {
                let case = format!("{version:?} store={store} {label}");
                let log = Log::default();
                archive
                    .extract_to_parallel_buffered_with_options(options, log.open())
                    .unwrap();
                for (name, data) in &members {
                    log.assert_flushed_once_after(name, data.len(), &case);
                }
            }
        }
    }
}

/// [`three`] split into volumes, or for the legacy formats, whose volume
/// writer takes one member, its middle member alone.
fn three_volumes(version: ArchiveVersion, store: bool) -> Vec<Archive> {
    if version == ArchiveVersion::Rar50 {
        return volumes(three(version, store));
    }
    let mut builder = Builder::new(version).store(store);
    builder
        .add_bytes(b"failing".to_vec(), noise(4096, 77), None, None)
        .unwrap();
    volumes(builder)
}

/// Three members, the middle one 4 KiB.
fn three(version: ArchiveVersion, store: bool) -> Builder {
    let mut builder = Builder::new(version).store(store);
    for (name, data) in [
        (b"first".as_slice(), b"earlier output".to_vec()),
        (b"failing", noise(4096, 77)),
        (b"later", b"after the failure".to_vec()),
    ] {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
    }
    builder
}

fn corrupt_checksum(archive: &mut Archive, name: &[u8]) {
    match archive {
        Archive::Rar13(a) => {
            for entry in &mut a.entries {
                if entry.name == name {
                    entry.header.file_crc ^= 1;
                }
            }
        }
        Archive::Rar15To40(a) => {
            for block in &mut a.blocks {
                if let rars::rar15_40::Block::File(file) = block {
                    if file.name == name {
                        file.file_crc ^= 1;
                    }
                }
            }
        }
        Archive::Rar50Plus(a) => {
            for block in &mut a.blocks {
                if let rars::rar50::Block::File(file) = block {
                    if file.name == name {
                        file.hash = None;
                        file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_member_that_fails_its_checksum_is_not_flushed() {
    for version in VERSIONS {
        for store in [true, false] {
            let case = format!("{version:?} store={store}");
            let mut archive =
                ArchiveReader::read_owned(three(version, store).to_bytes().unwrap()).unwrap();
            corrupt_checksum(&mut archive, b"failing");

            // Streamed so every format writes the failing member's bytes first.
            let options = ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0);
            let log = Log::default();
            let error = archive
                .extract_to_with_options(options, log.open())
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ChecksumMismatch, "{case}");
            log.assert_flushed_once_after(b"first", 14, &case);
            assert_eq!(log.written(b"failing"), 4096, "{case}");
            log.assert_not_flushed(b"failing", &case);
            assert_eq!(log.opened(), [b"first".to_vec(), b"failing".to_vec()]);

            // Carried on past by a member error handler, and under salvage,
            // which delivers the whole member before reporting it.
            for salvage in [false, true] {
                let case = format!("{case} salvage={salvage}");
                let log = Log::default();
                let handler = |member: &ArchiveMember, error: &Error| log.handle(member, error);
                let options = ArchiveReadOptions::new()
                    .with_salvage(salvage)
                    .with_member_error_handler(&handler);
                for parallel in [false, true] {
                    let before = log.handled().len();
                    if parallel {
                        archive.extract_to_parallel_buffered_with_options(options, log.open())
                    } else {
                        archive.extract_to_with_options(options, log.open())
                    }
                    .unwrap();
                    assert_eq!(log.handled().len(), before + 1, "{case}");
                    assert_eq!(log.handled().last().unwrap(), b"failing", "{case}");
                }
                if salvage {
                    assert_eq!(log.written(b"failing"), 2 * 4096, "{case}");
                }
                log.assert_not_flushed(b"failing", &case);
                assert_eq!(log.flushes(b"first"), 2, "{case}");
                assert_eq!(log.flushes(b"later"), 2, "{case}");
            }

            // The explicit handler of controlled extraction.
            let log = Log::default();
            archive
                .extract_with_control_and_errors(
                    ArchiveReadOptions::new(),
                    |member| {
                        log.writer(&member.meta.name, None)
                            .map(ExtractionDecision::Extract)
                    },
                    |member, error| log.handle(member, error),
                )
                .unwrap();
            assert_eq!(log.handled(), [b"failing".to_vec()], "{case}");
            log.assert_not_flushed(b"failing", &case);
            log.assert_flushed_once_after(b"later", 17, &case);
        }
    }
}

#[test]
fn a_member_that_fails_to_decode_is_not_flushed() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let case = format!("{version:?}");
        let mut bytes = three(version, false).to_bytes().unwrap();
        let parsed = ArchiveReader::read(&bytes).unwrap();
        let range = match &parsed {
            Archive::Rar13(a) => a.entries[1].packed_range.clone(),
            Archive::Rar15To40(a) => a.files().nth(1).unwrap().packed_range.clone(),
            Archive::Rar50Plus(a) => a.files().nth(1).unwrap().block.data_range.clone(),
            _ => unreachable!(),
        };
        for at in [range.start + 1, range.start + range.len() / 2] {
            bytes[at] ^= 0x5a;
        }
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        let log = Log::default();
        let handler = |member: &ArchiveMember, error: &Error| log.handle(member, error);
        archive
            .extract_to_with_options(
                ArchiveReadOptions::new().with_member_error_handler(&handler),
                log.open(),
            )
            .unwrap();
        assert_eq!(log.handled(), [b"failing".to_vec()], "{case}");
        log.assert_not_flushed(b"failing", &case);
        log.assert_flushed_once_after(b"first", 14, &case);
        log.assert_flushed_once_after(b"later", 17, &case);
    }
}

#[test]
fn a_member_over_an_output_limit_is_not_flushed() {
    for version in VERSIONS {
        let case = format!("{version:?}");
        let archive = ArchiveReader::read_owned(three(version, false).to_bytes().unwrap()).unwrap();
        let log = Log::default();
        let handler = |member: &ArchiveMember, error: &Error| log.handle(member, error);
        let options = ArchiveReadOptions::new()
            .with_max_member_output_bytes(1000)
            .with_member_error_handler(&handler);
        archive
            .extract_to_with_options(options, log.open())
            .unwrap();
        assert_eq!(log.handled(), [b"failing".to_vec()], "{case}");
        log.assert_not_flushed(b"failing", &case);
        log.assert_flushed_once_after(b"first", 14, &case);
        log.assert_flushed_once_after(b"later", 17, &case);
    }
}

#[test]
fn a_rar5_member_with_no_checksum_is_flushed_once_its_data_is_written() {
    for store in [true, false] {
        let mut archive = archive(ArchiveVersion::Rar50, store, false);
        let Archive::Rar50Plus(a) = &mut archive else {
            unreachable!()
        };
        for block in &mut a.blocks {
            if let rars::rar50::Block::File(file) = block {
                file.hash = None;
                file.data_crc32 = None;
            }
        }
        for (label, options) in option_variants() {
            let case = format!("store={store} {label}");
            let log = Log::default();
            archive
                .extract_to_with_options(options, log.open())
                .unwrap();
            assert_files_flushed_once(&log, &case);
            let log = Log::default();
            archive
                .extract_to_parallel_buffered_with_options(options, log.open())
                .unwrap();
            assert_files_flushed_once(&log, &format!("{case} parallel"));
        }
    }
}

/// Whether `error`'s `source()` chain holds `MyError`, directly or as the
/// payload of an `io::Error` in it.
fn holds_my_error(error: &Error) -> bool {
    let mut link: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = link {
        if error.downcast_ref::<MyError>().is_some() {
            return true;
        }
        if let Some(io) = error.downcast_ref::<io::Error>() {
            if io.get_ref().is_some_and(|inner| inner.is::<MyError>()) {
                return true;
            }
        }
        link = error.source();
    }
    false
}

fn in_volume(error: &Error) -> bool {
    let mut link: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = link {
        if matches!(error.downcast_ref::<Error>(), Some(Error::InVolume { .. })) {
            return true;
        }
        link = error.source();
    }
    false
}

#[test]
fn a_flush_error_fails_that_member() {
    for version in VERSIONS {
        for store in [true, false] {
            let case = format!("{version:?} store={store}");
            let archive =
                ArchiveReader::read_owned(three(version, store).to_bytes().unwrap()).unwrap();
            let set = three_volumes(version, store);
            type Extract<'a> = dyn Fn(&Log, ArchiveReadOptions<'_>) -> rars::Result<()> + 'a;
            let apis: [(&str, &Extract<'_>); 4] = [
                ("extract_to_with_options", &|log, options| {
                    archive.extract_to_with_options(
                        options,
                        log.open_faulty(b"failing", Some(Fault::Flush)),
                    )
                }),
                (
                    "extract_to_parallel_buffered_with_options",
                    &|log, options| {
                        archive.extract_to_parallel_buffered_with_options(
                            options,
                            log.open_faulty(b"failing", Some(Fault::Flush)),
                        )
                    },
                ),
                ("extract_volumes_to_with_options", &|log, options| {
                    rars::extract_volumes_to_with_options(
                        &set,
                        options,
                        log.open_faulty(b"failing", Some(Fault::Flush)),
                    )
                }),
                ("extract_with_volumes", &|log, options| {
                    set[0].extract_with_volumes(
                        set[1..].iter().cloned().map(Ok),
                        options,
                        log.open_faulty(b"failing", Some(Fault::Flush)),
                    )
                }),
            ];
            for (api, extract) in apis {
                let case = format!("{case} {api}");
                let log = Log::default();
                let error = extract(&log, ArchiveReadOptions::new()).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Io, "{case}: {error:?}");
                assert_eq!(error.entry_context().unwrap().0, b"failing", "{case}");
                assert!(holds_my_error(&error), "{case}: {error:?}");
                log.assert_flushed_once_after(b"failing", 4096, &case);
                assert!(!log.opened().contains(&b"later".to_vec()), "{case}");

                // A member error handler hears of it and carries on, except
                // for a split member, whose output errors stay fatal.
                let log = Log::default();
                let handler = |member: &ArchiveMember, error: &Error| log.handle(member, error);
                let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
                let result = extract(&log, options);
                if api.contains("volume") {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::Io, "{case}: {error:?}");
                    assert!(log.handled().is_empty(), "{case}");
                } else {
                    result.unwrap();
                    assert_eq!(log.handled(), [b"failing".to_vec()], "{case}");
                    log.assert_flushed_once_after(b"later", 17, &case);
                }
                assert_eq!(log.flushes(b"failing"), 1, "{case}");
            }
        }
    }
}

#[test]
fn the_callers_own_error_survives_in_the_source_chain() {
    for version in VERSIONS {
        for store in [true, false] {
            let archive =
                ArchiveReader::read_owned(three(version, store).to_bytes().unwrap()).unwrap();
            let set = three_volumes(version, store);
            for (fault, label) in [
                (Fault::Open, "open"),
                (Fault::Write, "write"),
                (Fault::Flush, "flush"),
            ] {
                let case = format!("{version:?} store={store} {label}");
                let log = Log::default();
                let error = archive
                    .extract_to(None, log.open_faulty(b"failing", Some(fault)))
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Io, "{case}: {error:?}");
                assert!(matches!(error.root_cause(), Error::Io(_)), "{case}");
                assert!(holds_my_error(&error), "{case}: {error:?}");

                // Across volumes, with the per-volume wrapper around a member's error.
                let log = Log::default();
                let error = set[0]
                    .extract_with_volumes(
                        set[1..].iter().cloned().map(Ok),
                        ArchiveReadOptions::new(),
                        log.open_faulty(b"failing", Some(fault)),
                    )
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Io, "{case}: {error:?}");
                assert!(holds_my_error(&error), "{case}: {error:?}");
                if error.entry_context().is_some() {
                    assert!(in_volume(&error), "{case}: {error:?}");
                }
            }
        }
    }
}
