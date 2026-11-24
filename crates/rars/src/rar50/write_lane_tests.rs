use super::*;
use crate::{ArchiveVersion, ExtractionErrorAction};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

#[derive(Debug, Clone, PartialEq)]
enum Event {
    Opened(Vec<u8>),
    Settled(Vec<u8>, bool),
    Handled(Vec<u8>),
}

#[derive(Default)]
struct Log {
    files: Vec<(Vec<u8>, Vec<u8>)>,
    events: Vec<Event>,
    wrote_elsewhere: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    Refuse,
    Panic,
}

struct Output {
    log: Arc<Mutex<Log>>,
    index: usize,
    fault: Option<Fault>,
    caller: ThreadId,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.fault {
            Some(Fault::Refuse) => return Err(std::io::Error::other("refused")),
            Some(Fault::Panic) => panic!("output panicked"),
            None => {}
        }
        let mut log = self.log.lock().unwrap();
        log.wrote_elsewhere |= std::thread::current().id() != self.caller;
        log.files[self.index].1.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Run {
    files: Vec<(Vec<u8>, Vec<u8>)>,
    events: Vec<Event>,
    error: Option<String>,
    wrote_elsewhere: bool,
}

fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut word = 0x1357_9bdfu32;
    let mut next = || {
        word ^= word << 13;
        word ^= word >> 17;
        word ^= word << 5;
        word
    };
    let words: [&[u8]; 5] = [b"lane ", b"write ", b"solid ", b"the ", b"of "];
    (0..24)
        .map(|index| {
            let len = 300 + next() as usize % 2_000;
            let mut data = Vec::new();
            while data.len() < len {
                data.extend_from_slice(words[next() as usize % words.len()]);
            }
            data.truncate(len);
            (format!("member-{index:02}.txt").into_bytes(), data)
        })
        .collect()
}

fn archive(members: &[(Vec<u8>, Vec<u8>)]) -> Archive {
    Archive::parse_owned(archive_bytes(members)).unwrap()
}

fn archive_bytes(members: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut builder = crate::Builder::new(ArchiveVersion::Rar50)
        .store(false)
        .solid(true)
        .compression_level(Some(3));
    for (name, data) in members {
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
    }
    builder.to_bytes().unwrap()
}

#[derive(Clone, Copy, Default)]
struct Setup<'n> {
    faulty: Option<(&'n [u8], Fault)>,
    cancel_after_settles: Option<usize>,
    action: Option<ExtractionErrorAction>,
}

fn run(archive: &Archive, threads: usize, setup: Setup<'_>) -> Run {
    let log = Arc::new(Mutex::new(Log::default()));
    let caller = std::thread::current().id();
    let cancellation = crate::ReadCancellation::new();
    let action = setup.action.unwrap_or(ExtractionErrorAction::Abort);
    let handler = |member: &crate::ArchiveMember, _: &Error| {
        let name = member.meta.name.clone();
        log.lock().unwrap().events.push(Event::Handled(name));
        Ok(action)
    };
    let options = crate::ArchiveReadOptions::new()
        .with_threads(threads)
        .with_rar50_buffered_decode_limit(1 << 20)
        .with_cancellation(&cancellation)
        .with_member_error_handler(&handler);
    let result = crate::output_links::extract_rar50_settled_with_links(
        archive,
        options,
        |meta| {
            let mut opened = log.lock().unwrap();
            opened.events.push(Event::Opened(meta.name.clone()));
            opened.files.push((meta.name.clone(), Vec::new()));
            Ok(Box::new(Output {
                log: Arc::clone(&log),
                index: opened.files.len() - 1,
                fault: setup
                    .faulty
                    .filter(|(name, _)| *name == meta.name.as_slice())
                    .map(|(_, fault)| fault),
                caller,
            }))
        },
        |_, _| Ok(()),
        |meta, verified| {
            let mut log = log.lock().unwrap();
            log.events.push(Event::Settled(meta.name.clone(), verified));
            let settles = log
                .events
                .iter()
                .filter(|event| matches!(event, Event::Settled(..)))
                .count();
            if setup.cancel_after_settles == Some(settles) {
                cancellation.cancel();
            }
            Ok(())
        },
    );
    let log = std::mem::take(&mut *log.lock().unwrap());
    Run {
        files: log.files,
        events: log.events,
        error: result.err().map(|error| error.to_string()),
        wrote_elsewhere: log.wrote_elsewhere,
    }
}

fn assert_lane_matches_serial(archive: &Archive, setup: Setup<'_>) -> Run {
    let serial = run(archive, 1, setup);
    assert!(!serial.wrote_elsewhere);
    let lane = run(archive, 4, setup);
    assert_eq!(
        lane.events, serial.events,
        "opens, settles and handler calls"
    );
    assert_eq!(lane.files, serial.files, "outputs");
    assert_eq!(lane.error, serial.error, "error");
    lane
}

#[test]
fn a_solid_chain_is_written_off_the_calling_thread_as_it_is_serially() {
    let members = members();
    let lane = assert_lane_matches_serial(&archive(&members), Setup::default());
    assert_eq!(lane.files, members);
    assert!(lane.wrote_elsewhere);
}

#[test]
fn an_output_that_fails_settles_as_it_does_serially() {
    let members = members();
    let archive = archive(&members);
    for failing in [0, 1, 9, members.len() - 1] {
        let name = members[failing].0.as_slice();
        for action in [
            ExtractionErrorAction::Abort,
            ExtractionErrorAction::Continue,
        ] {
            let setup = Setup {
                faulty: Some((name, Fault::Refuse)),
                action: Some(action),
                ..Setup::default()
            };
            let lane = assert_lane_matches_serial(&archive, setup);
            assert!(lane.events.contains(&Event::Handled(name.to_vec())));
        }
    }
}

#[test]
fn a_damaged_member_settles_as_it_does_serially() {
    let members = members();
    let bytes = archive_bytes(&members);
    let parsed = Archive::parse_owned(bytes.clone()).unwrap();
    let ranges: Vec<_> = parsed
        .files()
        .map(|file| file.block.data_range.clone())
        .collect();
    let mut handled = 0;
    for range in ranges.iter().skip(2).step_by(7) {
        for at in [range.start, range.start + range.len() / 2, range.end - 1] {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x10;
            let archive = Archive::parse_owned(damaged).unwrap();
            for action in [
                ExtractionErrorAction::Abort,
                ExtractionErrorAction::Continue,
            ] {
                let setup = Setup {
                    action: Some(action),
                    ..Setup::default()
                };
                let lane = assert_lane_matches_serial(&archive, setup);
                handled += usize::from(lane.events.iter().any(|e| matches!(e, Event::Handled(_))));
            }
        }
    }
    assert!(handled > 4, "handled {handled}");
}

#[test]
fn cancelling_mid_chain_stops_where_it_stops_serially() {
    let members = members();
    let archive = archive(&members);
    for settles in [1, 2, 11, members.len() - 1] {
        let setup = Setup {
            cancel_after_settles: Some(settles),
            ..Setup::default()
        };
        let lane = assert_lane_matches_serial(&archive, setup);
        assert!(lane.error.is_some());
    }
}

#[test]
fn a_panic_writing_an_output_reaches_the_caller() {
    let members = members();
    let archive = archive(&members);
    let setup = Setup {
        faulty: Some((members[3].0.as_slice(), Fault::Panic)),
        ..Setup::default()
    };
    for threads in [1, 4] {
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&archive, threads, setup)
        }));
        assert!(ran.is_err(), "threads={threads}");
    }
}
