#![cfg(feature = "write")]

#[path = "support/sinks.rs"]
mod sinks;
use sinks::SyncCapture;

use rars::output_links::{extract_settled, settle_in_order, Select, Settled, SettledSource};
use rars::{
    ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind, ExtractionErrorAction,
    ReadCancellation,
};
use std::sync::{Arc, Mutex};

type Opened = Arc<Mutex<Vec<(Vec<u8>, Arc<Mutex<Vec<u8>>>)>>>;

struct Run {
    events: Vec<String>,
    kept: Vec<(String, Vec<u8>)>,
    result: Result<(), ErrorKind>,
}

fn run(source: SettledSource<'_>, options: ArchiveReadOptions<'_>) -> Run {
    run_with(source, options, Case::default())
}

#[derive(Default, Clone, Copy)]
struct Case<'a> {
    on_error: Option<ExtractionErrorAction>,
    select: Option<&'a Select<'a>>,
    cancel_at: Option<(&'a str, &'a ReadCancellation)>,
    in_order: bool,
}

fn run_with(source: SettledSource<'_>, options: ArchiveReadOptions<'_>, case: Case<'_>) -> Run {
    let Case {
        on_error,
        select,
        cancel_at,
        in_order,
    } = case;
    let events = Arc::new(Mutex::new(Vec::new()));
    let handler = |member: &rars::ArchiveMember, _: &rars::Error| {
        let event = format!("fail {}", name(&member.meta.name));
        events.lock().unwrap().push(event);
        Ok(on_error.expect("handler set only with an answer"))
    };
    let options = match on_error {
        Some(_) => options.with_member_error_handler(&handler),
        None => options,
    };
    let opened: Opened = Arc::default();
    let kept = Arc::new(Mutex::new(Vec::new()));
    let open = |meta: &rars::ExtractedEntryMeta| -> rars::Result<Box<dyn std::io::Write + Send>> {
        let data = Arc::new(Mutex::new(Vec::new()));
        opened
            .lock()
            .unwrap()
            .push((meta.name.clone(), data.clone()));
        events
            .lock()
            .unwrap()
            .push(format!("open {}", name(&meta.name)));
        if let Some((at, token)) = cancel_at {
            if meta.name == at.as_bytes() {
                token.cancel();
            }
        }
        Ok(Box::new(SyncCapture(data)))
    };
    let link = |meta: &rars::ExtractedEntryMeta, link: rars::ExtractedLink<'_>| {
        let event = format!("link {} {}", name(&meta.name), name(link.target()));
        events.lock().unwrap().push(event);
        Ok(())
    };
    let settled = {
        let events = events.clone();
        let opened = opened.clone();
        let kept = kept.clone();
        move |meta: &rars::ExtractedEntryMeta, outcome| {
            let mut opened = opened.lock().unwrap();
            assert!(!opened.is_empty(), "only opened members settle");
            let (opened_name, data) = opened.remove(0);
            assert_eq!(
                opened_name, meta.name,
                "members settle in the order they open"
            );
            let event = format!("settle {} {outcome:?}", name(&meta.name));
            events.lock().unwrap().push(event);
            if outcome != Settled::Failed {
                assert_eq!(
                    Arc::strong_count(&data),
                    1,
                    "a member's writer is dropped before it settles"
                );
                let output = data.lock().unwrap().clone();
                kept.lock().unwrap().push((name(&meta.name), output));
            }
            Ok(())
        }
    };
    let result = if in_order {
        assert!(select.is_none(), "the walk driven chooses nothing");
        settle_in_order(
            options,
            open,
            link,
            settled,
            |read, open, link| match source {
                SettledSource::Archive(archive) => archive.extract_with_links(read, open, link),
                SettledSource::Volumes(volumes) => {
                    rars::extract_volumes_with_links(volumes, read, open, link)
                }
            },
        )
    } else {
        extract_settled(source, options, select, open, link, settled)
    };
    assert!(
        opened.lock().unwrap().is_empty(),
        "every member opened settles"
    );
    let events = std::mem::take(&mut *events.lock().unwrap());
    let kept = std::mem::take(&mut *kept.lock().unwrap());
    Run {
        events,
        kept,
        result: result.map_err(|error| error.kind()),
    }
}

fn name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn archive(version: ArchiveVersion, members: &[(&str, &[u8])]) -> rars::Archive {
    let mut builder = Builder::new(version).store(true);
    for (member, data) in members {
        builder
            .add_bytes(member.as_bytes().to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

#[test]
fn every_member_opened_settles_verified_in_archive_order() {
    let archive = archive(ArchiveVersion::Rar29, &[("a", b"first"), ("b", b"second")]);

    let run = run(SettledSource::Archive(&archive), ArchiveReadOptions::new());

    assert_eq!(run.result, Ok(()));
    assert_eq!(
        run.events,
        ["open a", "settle a Verified", "open b", "settle b Verified"]
    );
    assert_eq!(
        run.kept,
        [
            ("a".to_string(), b"first".to_vec()),
            ("b".to_string(), b"second".to_vec())
        ]
    );
}

const FAMILIES: [ArchiveVersion; 5] = [
    ArchiveVersion::Rar13,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

const VOLUME_FAMILIES: [ArchiveVersion; 4] = [
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

const BROKEN: &[u8] = b"this member's stored bytes get one flipped";

fn break_member(mut bytes: Vec<u8>) -> Vec<u8> {
    let at = bytes
        .windows(BROKEN.len())
        .position(|window| window == BROKEN)
        .expect("stored payload is in the archive");
    bytes[at + 4] ^= 1;
    bytes
}

fn with_a_broken_member(version: ArchiveVersion) -> rars::Archive {
    let mut builder = Builder::new(version).store(true);
    for (member, data) in [("a", &b"first"[..]), ("bad", BROKEN), ("c", b"third")] {
        builder
            .add_bytes(member.as_bytes().to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    ArchiveReader::read_owned(break_member(builder.to_bytes().unwrap())).unwrap()
}

// Parallel decoding opens members ahead of the ones settling, and never opens
// one that fails, so opens and a failed member's own settle are left out.
fn settled_order(events: &[String]) -> Vec<String> {
    for (index, event) in events.iter().enumerate() {
        let Some(member) = event
            .strip_prefix("settle ")
            .and_then(|e| e.strip_suffix(" Failed"))
        else {
            continue;
        };
        assert!(
            events[..index].contains(&format!("open {member}")),
            "{events:?}"
        );
        if let Some(next) = events.get(index + 1) {
            if next.starts_with("fail ") {
                assert_eq!(*next, format!("fail {member}"), "{events:?}");
            }
        }
    }
    events
        .iter()
        .filter(|event| !event.starts_with("open ") && !event.ends_with(" Failed"))
        .cloned()
        .collect()
}

fn threads() -> [usize; 3] {
    [1, 2, 8]
}

#[test]
fn a_failed_member_settles_failed_before_the_handler_hears_of_it() {
    for version in FAMILIES {
        let archive = with_a_broken_member(version);
        for threads in threads() {
            let case = format!("{version:?} threads={threads}");
            let options = ArchiveReadOptions::new().with_threads(threads);
            let source = SettledSource::Archive(&archive);

            let carried_on = run_with(source, options, continuing());
            assert_eq!(carried_on.result, Ok(()), "{case}");
            assert_eq!(
                settled_order(&carried_on.events),
                ["settle a Verified", "fail bad", "settle c Verified"],
                "{case}: {:?}",
                carried_on.events
            );

            let aborted = run_with(
                source,
                options,
                Case {
                    on_error: Some(ExtractionErrorAction::Abort),
                    ..Case::default()
                },
            );
            assert_eq!(aborted.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert_eq!(
                settled_order(&aborted.events),
                ["settle a Verified", "fail bad"],
                "{case}: {:?}",
                aborted.events
            );

            let unhandled = run(source, options);
            assert_eq!(unhandled.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert_eq!(
                settled_order(&unhandled.events),
                ["settle a Verified"],
                "{case}: {:?}",
                unhandled.events
            );
            assert_eq!(
                unhandled.kept,
                [("a".to_string(), b"first".to_vec())],
                "{case}"
            );
        }
    }
}

fn continuing<'a>() -> Case<'a> {
    Case {
        on_error: Some(ExtractionErrorAction::Continue),
        ..Case::default()
    }
}

#[test]
fn a_link_after_a_failed_member_comes_once_it_has_settled() {
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"a".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"bad".to_vec(), BROKEN.to_vec(), None, None)
            .unwrap();
        builder
            .add_unix_symlink(b"link".to_vec(), b"a".to_vec(), false, None, None)
            .unwrap();
        builder
            .add_bytes(b"c".to_vec(), b"third".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(break_member(builder.to_bytes().unwrap())).unwrap();
        for threads in threads() {
            let options = ArchiveReadOptions::new().with_threads(threads);

            let run = run_with(SettledSource::Archive(&archive), options, continuing());

            assert_eq!(run.result, Ok(()), "{version:?} threads={threads}");
            assert_eq!(
                settled_order(&run.events),
                [
                    "settle a Verified",
                    "fail bad",
                    "link link a",
                    "settle c Verified"
                ],
                "{version:?} threads={threads}: {:?}",
                run.events
            );
        }
    }
}

#[test]
fn cancelling_settles_what_was_opened_and_stops() {
    for version in FAMILIES {
        let archive = archive(
            version,
            &[("a", b"first"), ("b", b"second"), ("c", b"third")],
        );
        for threads in threads() {
            let token = ReadCancellation::new();
            let options = ArchiveReadOptions::new()
                .with_threads(threads)
                .with_cancellation(&token);

            let run = run_with(
                SettledSource::Archive(&archive),
                options,
                Case {
                    cancel_at: Some(("b", &token)),
                    ..continuing()
                },
            );

            let case = format!("{version:?} threads={threads}");
            assert_eq!(run.result, Err(ErrorKind::Cancelled), "{case}");
            assert!(
                !run.events.iter().any(|event| event == "open c"),
                "{case}: {:?}",
                run.events
            );
            assert!(
                !run.events
                    .iter()
                    .any(|event| event.starts_with("settle b Verified")),
                "{case}: {:?}",
                run.events
            );
        }
    }
}

fn filler(len: usize) -> Vec<u8> {
    (0..len).map(|n| (n * 7 % 251) as u8).collect()
}

fn read_volumes(volumes: Vec<Vec<u8>>) -> Vec<rars::Archive> {
    let mut volumes = volumes;
    let holding = volumes
        .iter()
        .position(|volume| volume.windows(BROKEN.len()).any(|w| w == BROKEN))
        .expect("the broken payload sits whole in one volume");
    volumes[holding] = break_member(std::mem::take(&mut volumes[holding]));
    volumes
        .into_iter()
        .map(|volume| ArchiveReader::read_owned(volume).unwrap())
        .collect()
}

// RAR 5 volume writing makes no links, and RAR 1.5 has none.
fn has_link(version: ArchiveVersion) -> bool {
    !matches!(version, ArchiveVersion::Rar15 | ArchiveVersion::Rar50)
}

fn volume_set(version: ArchiveVersion) -> Vec<rars::Archive> {
    use rars::rar15_40::{
        write_volumes_to, CollectedVolumes, EntrySource, MemberCoding, StreamingEntry,
        WriterOptions,
    };
    let members: [(&str, Vec<u8>); 3] = [
        ("a", b"first".to_vec()),
        ("bad", BROKEN.to_vec()),
        ("c", filler(6000)),
    ];
    if version.family() == rars::ArchiveFamily::Rar50Plus {
        let mut builder = Builder::new(version).store(true).volume_size(Some(3000));
        for (member, data) in members {
            builder
                .add_bytes(member.as_bytes().to_vec(), data, None, None)
                .unwrap();
        }
        return read_volumes(builder.build_volumes(None).unwrap());
    }
    let entry = |member: &str, data: Vec<u8>, attr: u32, host: u8| {
        StreamingEntry::new(member.as_bytes().to_vec(), EntrySource::from_bytes(data))
            .with_file_attr(attr)
            .with_host_os(host)
    };
    let mut entries: Vec<StreamingEntry> = members
        .into_iter()
        .map(|(member, data)| entry(member, data, 0o100644, 3))
        .collect();
    if has_link(version) {
        entries.insert(2, entry("link", b"a".to_vec(), 0o120777, 3));
    }
    let mut sink = CollectedVolumes::new();
    write_volumes_to(
        &entries,
        WriterOptions::new(version, rars::FeatureSet::store_only()),
        MemberCoding::Stored,
        3000,
        &mut sink,
        &rars::WriterResources::default(),
        None,
    )
    .unwrap();
    read_volumes(sink.take())
}

#[test]
fn volume_sets_settle_as_single_archives_do() {
    for version in VOLUME_FAMILIES {
        let volumes = volume_set(version);
        assert!(volumes.len() > 1, "{version:?}");
        for threads in threads() {
            let case = format!("{version:?} threads={threads}");
            let options = ArchiveReadOptions::new().with_threads(threads);
            let source = SettledSource::Volumes(&volumes);

            let carried_on = run_with(source, options, continuing());
            assert_eq!(carried_on.result, Ok(()), "{case}");
            let mut expected = vec!["settle a Verified", "fail bad", "settle c Verified"];
            if has_link(version) {
                expected.insert(2, "link link a");
            }
            assert_eq!(
                settled_order(&carried_on.events),
                expected,
                "{case}: {:?}",
                carried_on.events
            );
            assert_eq!(
                carried_on.kept,
                [
                    ("a".to_string(), b"first".to_vec()),
                    ("c".to_string(), filler(6000))
                ],
                "{case}"
            );

            let aborted = run_with(
                source,
                options,
                Case {
                    on_error: Some(ExtractionErrorAction::Abort),
                    ..Case::default()
                },
            );
            assert_eq!(aborted.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert_eq!(
                settled_order(&aborted.events),
                ["settle a Verified", "fail bad"],
                "{case}: {:?}",
                aborted.events
            );

            let unhandled = run(source, options);
            assert_eq!(unhandled.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert_eq!(
                settled_order(&unhandled.events),
                ["settle a Verified"],
                "{case}: {:?}",
                unhandled.events
            );
        }
    }
}

#[test]
fn a_rar13_volume_set_settles_its_split_member() {
    let mut data = BROKEN.to_vec();
    data.extend(filler(6000));
    let mut builder = Builder::new(ArchiveVersion::Rar13)
        .store(true)
        .volume_size(Some(4096));
    builder
        .add_bytes(b"bad".to_vec(), data, None, None)
        .unwrap();
    let volumes = read_volumes(builder.build_volumes(None).unwrap());
    let clean = {
        let mut builder = Builder::new(ArchiveVersion::Rar13)
            .store(true)
            .volume_size(Some(4096));
        builder
            .add_bytes(b"whole".to_vec(), filler(6000), None, None)
            .unwrap();
        builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|volume| ArchiveReader::read_owned(volume).unwrap())
            .collect::<Vec<_>>()
    };
    for threads in threads() {
        let options = ArchiveReadOptions::new().with_threads(threads);

        let whole = run(SettledSource::Volumes(&clean), options);
        assert_eq!(whole.result, Ok(()));
        assert_eq!(whole.events, ["open whole", "settle whole Verified"]);

        let carried_on = run_with(SettledSource::Volumes(&volumes), options, continuing());
        assert_eq!(carried_on.result, Ok(()));
        assert_eq!(
            carried_on.events,
            ["open bad", "settle bad Failed", "fail bad"]
        );
    }
}

#[test]
fn salvage_keeps_a_member_the_handler_carries_on_past() {
    let mut damaged = BROKEN.to_vec();
    damaged[4] ^= 1;
    for version in FAMILIES {
        let archive = with_a_broken_member(version);
        for threads in threads() {
            let case = format!("{version:?} threads={threads}");
            let options = ArchiveReadOptions::new()
                .with_threads(threads)
                .with_salvage(true);
            let source = SettledSource::Archive(&archive);

            let carried_on = run_with(source, options, continuing());
            assert_eq!(carried_on.result, Ok(()), "{case}");
            assert_eq!(
                carried_on.events,
                [
                    "open a",
                    "settle a Verified",
                    "open bad",
                    "fail bad",
                    "settle bad KeptBroken",
                    "open c",
                    "settle c Verified"
                ],
                "{case}"
            );
            assert_eq!(
                carried_on.kept[1],
                ("bad".to_string(), damaged.clone()),
                "{case}"
            );

            let aborted = run_with(
                source,
                options,
                Case {
                    on_error: Some(ExtractionErrorAction::Abort),
                    ..Case::default()
                },
            );
            assert_eq!(aborted.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert_eq!(
                aborted.events,
                [
                    "open a",
                    "settle a Verified",
                    "open bad",
                    "fail bad",
                    "settle bad Failed"
                ],
                "{case}"
            );
        }
    }
}

fn only<'a>(indices: &'a [usize]) -> impl Fn(usize, &rars::ArchiveMember) -> bool + 'a {
    move |index, _| indices.contains(&index)
}

#[test]
fn a_selection_opens_only_what_it_chooses_and_reads_no_further() {
    for version in FAMILIES {
        let archive = with_a_broken_member(version);
        for threads in threads() {
            let case = format!("{version:?} threads={threads}");
            let options = ArchiveReadOptions::new().with_threads(threads);
            let source = SettledSource::Archive(&archive);

            let first = only(&[0]);
            let before_the_damage = run_with(
                source,
                options,
                Case {
                    select: Some(&first),
                    ..Case::default()
                },
            );
            assert_eq!(before_the_damage.result, Ok(()), "{case}");
            assert_eq!(
                before_the_damage.events,
                ["open a", "settle a Verified"],
                "{case}"
            );

            let last = only(&[2]);
            let past_the_damage = run_with(
                source,
                options,
                Case {
                    select: Some(&last),
                    ..Case::default()
                },
            );
            assert_eq!(past_the_damage.result, Ok(()), "{case}");
            assert_eq!(
                past_the_damage.events,
                ["open c", "settle c Verified"],
                "{case}"
            );
        }
    }
}

#[test]
fn a_solid_member_left_out_still_feeds_the_ones_after_it() {
    let text = |n: u8| b"solid history carries over ".repeat(40 + usize::from(n));
    for version in FAMILIES {
        let mut builder = Builder::new(version).solid(true);
        for (index, member) in ["a", "b", "c"].into_iter().enumerate() {
            builder
                .add_bytes(member.as_bytes().to_vec(), text(index as u8), None, None)
                .unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(archive.is_solid(), "{version:?}");
        let last = only(&[2]);

        for threads in threads() {
            let run = run_with(
                SettledSource::Archive(&archive),
                ArchiveReadOptions::new().with_threads(threads),
                Case {
                    select: Some(&last),
                    ..Case::default()
                },
            );

            assert_eq!(run.result, Ok(()), "{version:?} threads={threads}");
            assert_eq!(
                run.events,
                ["open c", "settle c Verified"],
                "{version:?} threads={threads}"
            );
            assert_eq!(
                run.kept,
                [("c".to_string(), text(2))],
                "{version:?} threads={threads}"
            );
        }
    }
}

#[test]
fn a_selection_over_a_volume_set_leaves_out_members_and_links() {
    for version in VOLUME_FAMILIES {
        let volumes = volume_set(version);
        let c = if has_link(version) { 3 } else { 2 };
        let chosen = [0, c];
        let select = only(&chosen);

        for threads in threads() {
            let run = run_with(
                SettledSource::Volumes(&volumes),
                ArchiveReadOptions::new().with_threads(threads),
                Case {
                    select: Some(&select),
                    ..continuing()
                },
            );

            assert_eq!(run.result, Ok(()), "{version:?} threads={threads}");
            assert!(
                !run.events
                    .iter()
                    .any(|event| event.starts_with("open bad") || event.starts_with("link ")),
                "{version:?} threads={threads}: {:?}",
                run.events
            );
            assert_eq!(
                run.kept,
                [
                    ("a".to_string(), b"first".to_vec()),
                    ("c".to_string(), filler(6000))
                ],
                "{version:?} threads={threads}"
            );
        }
    }
}

#[test]
fn a_selected_link_after_a_failed_selected_member_comes_once_it_has_settled() {
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        for (member, data) in [
            ("a", &b"first"[..]),
            ("skipped", b"second"),
            ("bad", BROKEN),
        ] {
            builder
                .add_bytes(member.as_bytes().to_vec(), data.to_vec(), None, None)
                .unwrap();
        }
        builder
            .add_unix_symlink(b"link".to_vec(), b"a".to_vec(), false, None, None)
            .unwrap();
        builder
            .add_bytes(b"c".to_vec(), b"third".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(break_member(builder.to_bytes().unwrap())).unwrap();
        let chosen = only(&[0, 2, 3, 4]);

        for threads in threads() {
            let run = run_with(
                SettledSource::Archive(&archive),
                ArchiveReadOptions::new().with_threads(threads),
                Case {
                    select: Some(&chosen),
                    ..continuing()
                },
            );

            assert_eq!(run.result, Ok(()), "{version:?} threads={threads}");
            assert_eq!(
                run.events,
                [
                    "open a",
                    "settle a Verified",
                    "open bad",
                    "settle bad Failed",
                    "fail bad",
                    "link link a",
                    "open c",
                    "settle c Verified"
                ],
                "{version:?} threads={threads}"
            );
        }
    }
}

#[test]
fn a_selected_legacy_link_is_made_before_a_later_member_aborts() {
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar29] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"a".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder
            .add_unix_symlink(b"link".to_vec(), b"a".to_vec(), false, None, None)
            .unwrap();
        builder
            .add_bytes(b"bad".to_vec(), BROKEN.to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(break_member(builder.to_bytes().unwrap())).unwrap();
        let all = only(&[0, 1, 2]);

        let run = run_with(
            SettledSource::Archive(&archive),
            ArchiveReadOptions::new(),
            Case {
                on_error: Some(ExtractionErrorAction::Abort),
                select: Some(&all),
                ..Case::default()
            },
        );

        assert_eq!(run.result, Err(ErrorKind::ChecksumMismatch), "{version:?}");
        assert_eq!(
            run.events,
            [
                "open a",
                "settle a Verified",
                "link link a",
                "open bad",
                "settle bad Failed",
                "fail bad"
            ],
            "{version:?}"
        );
    }
}

// Writing in place or flattened needs every earlier member settled before the next opens.
fn opened_one_at_a_time(events: &[String]) -> bool {
    let mut open = 0usize;
    for event in events {
        if event.starts_with("open ") {
            if open > 0 {
                return false;
            }
            open += 1;
        } else if event.starts_with("settle ") {
            open -= 1;
        }
    }
    true
}

#[test]
fn settling_in_order_opens_each_member_once_the_one_before_has_settled() {
    let volume_sets = VOLUME_FAMILIES.map(volume_set);
    let archives = FAMILIES.map(with_a_broken_member);
    let sources = archives
        .iter()
        .map(SettledSource::Archive)
        .chain(volume_sets.iter().map(|set| SettledSource::Volumes(set)));
    for source in sources {
        for threads in threads() {
            let options = ArchiveReadOptions::new().with_threads(threads);
            let in_order = |on_error| Case {
                on_error,
                in_order: true,
                ..Case::default()
            };

            let carried_on = run_with(
                source,
                options,
                in_order(Some(ExtractionErrorAction::Continue)),
            );
            let case = format!("{source:?} threads={threads}: {:?}", carried_on.events);
            assert_eq!(carried_on.result, Ok(()), "{case}");
            assert!(opened_one_at_a_time(&carried_on.events), "{case}");
            let kept: Vec<_> = carried_on
                .kept
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(kept, ["a", "c"], "{case}");

            let unhandled = run_with(source, options, in_order(None));
            let case = format!("{source:?} threads={threads}: {:?}", unhandled.events);
            assert_eq!(unhandled.result, Err(ErrorKind::ChecksumMismatch), "{case}");
            assert!(opened_one_at_a_time(&unhandled.events), "{case}");
            assert_eq!(
                settled_order(&unhandled.events),
                ["settle a Verified"],
                "{case}"
            );
        }
    }
}

#[test]
fn a_selected_legacy_link_is_made_when_the_next_member_fails_before_it_opens() {
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar29] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"a".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder
            .add_unix_symlink(b"link".to_vec(), b"a".to_vec(), false, None, None)
            .unwrap();
        builder
            .add_bytes(b"secret".to_vec(), b"hidden".to_vec(), None, None)
            .unwrap();
        builder
            .set_entry_encryption(b"secret", Some(b"password".to_vec()), None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let all = only(&[0, 1, 2]);

        let run = run_with(
            SettledSource::Archive(&archive),
            ArchiveReadOptions::new(),
            Case {
                select: Some(&all),
                ..Case::default()
            },
        );

        assert_eq!(run.result, Err(ErrorKind::PasswordRequired), "{version:?}");
        assert!(
            run.events.iter().any(|event| event == "link link a"),
            "{version:?}: {:?}",
            run.events
        );
    }
}
