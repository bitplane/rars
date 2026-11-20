#![cfg(feature = "write")]

//! Volume sets with volumes missing: the members wholly inside the volumes
//! present still read, and the split ones are named.

use rars::rar15_40::{write_volumes_to, CollectedVolumes, EntrySource, StreamingEntry};
use rars::{
    drop_incomplete_members, extract_volumes_to_with_options, Archive, ArchiveReadOptions,
    ArchiveReader, ArchiveVersion, Builder, FeatureSet, MemberCoding, MissingPart, WriterResources,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Range;
use std::sync::{Arc, Mutex};

type Members = BTreeMap<Vec<u8>, Vec<u8>>;

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            // Half noise, half text, so compressed members still span volumes.
            if index % 2 == 0 {
                state as u8
            } else {
                b"partial volume set "[index % 19]
            }
        })
        .collect()
}

/// Sizes that leave some members inside one volume and split others over several.
const SIZES: [usize; 9] = [300, 9_000, 120, 2_500, 40, 14_000, 700, 3_000, 90];

fn members() -> Members {
    SIZES
        .iter()
        .enumerate()
        .map(|(index, &len)| (format!("m{index}").into_bytes(), noise(index as u32, len)))
        .collect()
}

fn legacy_set(version: ArchiveVersion, coding: MemberCoding) -> Vec<Vec<u8>> {
    let entries: Vec<_> = members()
        .into_iter()
        .map(|(name, data)| {
            StreamingEntry::new(name, EntrySource::from_bytes(data))
                .with_file_time(0x5a21_3c4d)
                .with_file_attr(0x20)
                .with_host_os(2)
        })
        .collect();
    let options = rars::rar15_40::WriterOptions::new(version, FeatureSet::store_only());
    let mut sink = CollectedVolumes::new();
    write_volumes_to(
        &entries,
        options,
        coding,
        4096,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    sink.take()
}

fn builder_set(version: ArchiveVersion, stored: bool, members: &Members) -> Vec<Vec<u8>> {
    let mut builder = Builder::new(version).store(stored).volume_size(Some(4096));
    for (name, data) in members {
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
    }
    builder.build_volumes(None).unwrap()
}

/// Every set with its members, named for failure messages.
fn sets() -> Vec<(String, Members, Vec<Vec<u8>>)> {
    let mut sets = Vec::new();
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
    ] {
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            sets.push((
                format!("{version:?} {coding:?}"),
                members(),
                legacy_set(version, coding),
            ));
        }
    }
    for stored in [true, false] {
        sets.push((
            format!("Rar50 stored={stored}"),
            members(),
            builder_set(ArchiveVersion::Rar50, stored, &members()),
        ));
    }
    // RAR 1.4 volumes hold one member, split across all of them.
    let lone: Members = [(b"lone".to_vec(), noise(7, 20_000))].into();
    sets.push((
        "Rar13".into(),
        lone.clone(),
        builder_set(ArchiveVersion::Rar13, true, &lone),
    ));
    sets
}

fn parse(volumes: &[Vec<u8>]) -> Vec<Archive> {
    volumes
        .iter()
        .map(|bytes| ArchiveReader::read_owned(bytes.clone()).unwrap())
        .collect()
}

/// The volumes holding part of each member, read from the complete set.
fn placement(archives: &[Archive]) -> BTreeMap<Vec<u8>, Range<usize>> {
    let mut placement: BTreeMap<Vec<u8>, Range<usize>> = BTreeMap::new();
    for (index, archive) in archives.iter().enumerate() {
        for member in archive.members() {
            placement
                .entry(member.meta.name)
                .and_modify(|range| range.end = index + 1)
                .or_insert(index..index + 1);
        }
    }
    placement
}

struct Collect(Arc<Mutex<Members>>, Vec<u8>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .entry(self.1.clone())
            .or_default()
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Extracts a run of volumes as the CLI does: a lone volume on its own.
fn extract(archives: &[Archive]) -> rars::Result<Members> {
    let outputs = Arc::new(Mutex::new(Members::new()));
    let open = |meta: &rars::ExtractedEntryMeta| {
        outputs
            .lock()
            .unwrap()
            .insert(meta.name.clone(), Vec::new());
        Ok(Box::new(Collect(outputs.clone(), meta.name.clone())) as Box<dyn Write>)
    };
    match archives {
        [archive] => archive.extract_to(None, open)?,
        _ => extract_volumes_to_with_options(archives, ArchiveReadOptions::new(), open)?,
    }
    let members = outputs.lock().unwrap().clone();
    Ok(members)
}

#[test]
fn sets_with_a_volume_missing_read_every_whole_member_and_name_the_split_ones() {
    for (label, members, volumes) in sets() {
        let count = volumes.len();
        assert!(count >= 4, "{label}: {count} volumes");
        let placement = placement(&parse(&volumes));
        assert!(
            placement.values().any(|range| range.len() > 1),
            "{label}: no member is split"
        );
        // The runs either side of a first, middle or last volume missing,
        // and every volume on its own, which reads as a single archive.
        let mut runs = Vec::new();
        for missing in [0, count / 2, count - 1] {
            runs.extend([0..missing, missing + 1..count]);
        }
        runs.extend((0..count).map(|volume| volume..volume + 1));
        for run in runs.into_iter().filter(|run| !run.is_empty()) {
            let case = format!("{label}, volumes {run:?} of {count}");
            let mut archives = parse(&volumes[run.clone()]);
            let incomplete = drop_incomplete_members(&mut archives);

            let mut whole = Members::new();
            let mut split = Vec::new();
            for (name, range) in &placement {
                if run.start <= range.start && range.end <= run.end {
                    whole.insert(name.clone(), members[name].clone());
                } else if range.start < run.end && run.start < range.end {
                    let missing = match (range.start < run.start, run.end < range.end) {
                        (true, true) => MissingPart::Both,
                        (true, false) => MissingPart::Start,
                        _ => MissingPart::End,
                    };
                    let volume = range.start.max(run.start) - run.start;
                    split.push((name.clone(), volume, missing));
                }
            }
            let reported: Vec<_> = incomplete
                .iter()
                .map(|member| (member.name.clone(), member.volume, member.missing))
                .collect();
            // Reported in archive order, which is also the order of the names.
            split.sort_by_key(|(name, volume, _)| (*volume, name.clone()));
            assert_eq!(reported, split, "{case}");
            assert_eq!(extract(&archives).unwrap(), whole, "{case}");
            if archives.len() > 1 {
                let mut tested = Vec::new();
                rars::test_volumes_with_options_and_callback(
                    &archives,
                    ArchiveReadOptions::new(),
                    |meta| {
                        tested.push(meta.name.clone());
                        Ok(())
                    },
                )
                .unwrap();
                tested.sort();
                assert_eq!(tested, whole.keys().cloned().collect::<Vec<_>>(), "{case}");
            } else {
                archives[0].test(None).unwrap();
            }
        }
    }
}

#[test]
fn a_complete_set_loses_nothing() {
    for (label, members, volumes) in sets() {
        let mut archives = parse(&volumes);
        assert_eq!(drop_incomplete_members(&mut archives), [], "{label}");
        assert_eq!(extract(&archives).unwrap(), members, "{label}");
    }
}

#[test]
fn a_continuation_of_another_member_is_a_break_in_the_set() {
    // RAR 1.5 and 2.0 volumes carry no number, so only the headers show that
    // a volume was skipped: the next one continues some other member.
    let mut checked = 0;
    for version in [ArchiveVersion::Rar15, ArchiveVersion::Rar20] {
        let volumes = legacy_set(version, MemberCoding::Stored);
        let placement = placement(&parse(&volumes));
        let runs_on = |volume: usize| {
            placement
                .iter()
                .find(|(_, range)| range.start <= volume && volume + 1 < range.end)
                .map(|(name, _)| name.clone())
        };
        let carried_into = |volume: usize| {
            placement
                .iter()
                .find(|(_, range)| range.start < volume && volume < range.end)
                .map(|(name, _)| name.clone())
        };
        for before in 0..volumes.len() - 2 {
            let after = before + 2;
            let (Some(ending), Some(starting)) = (runs_on(before), carried_into(after)) else {
                continue;
            };
            if ending == starting {
                continue;
            }
            let mut archives = parse(&[volumes[before].clone(), volumes[after].clone()]);
            let incomplete = drop_incomplete_members(&mut archives);
            let reported: Vec<_> = incomplete
                .iter()
                .map(|member| (member.name.clone(), member.missing))
                .collect();
            let case = format!("{version:?}, volumes {before} and {after}");
            assert!(
                reported.iter().any(|(name, missing)| *name == ending
                    && matches!(missing, MissingPart::End | MissingPart::Both)),
                "{case}: {reported:?}"
            );
            assert!(
                reported.iter().any(|(name, missing)| *name == starting
                    && matches!(missing, MissingPart::Start | MissingPart::Both)),
                "{case}: {reported:?}"
            );
            let extracted = extract(&archives).unwrap();
            assert!(!extracted.contains_key(&ending), "{case}");
            assert!(!extracted.contains_key(&starting), "{case}");
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no pair of volumes continues different members"
    );
}
