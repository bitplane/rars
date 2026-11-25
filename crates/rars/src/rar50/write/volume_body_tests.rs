//! A volume written straight into its output matches one whose body is
//! spooled and copied in when the volume closes. An output that cannot seek
//! still takes the spooled route, so the two are compared byte for byte.

use super::{write_streaming_volumes_to, ArchiveEntry, ArchiveExtras, WriterOptions};
use crate::rar50::{CollectedVolumes, VolumeOutput, VolumeSink};
use crate::{ArchiveReadOptions, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Collects volumes through outputs that refuse to seek.
#[derive(Default)]
struct Unseekable {
    volumes: Vec<Arc<Mutex<Vec<u8>>>>,
}

struct UnseekableVolume(Arc<Mutex<Vec<u8>>>);

impl Write for UnseekableVolume {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for UnseekableVolume {
    fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

impl VolumeSink for Unseekable {
    fn start_volume(&mut self, index: u64) -> crate::Result<Box<dyn VolumeOutput>> {
        assert_eq!(self.volumes.len() as u64, index);
        let volume = Arc::new(Mutex::new(Vec::new()));
        self.volumes.push(volume.clone());
        Ok(Box::new(UnseekableVolume(volume)))
    }
}

fn text(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|at| b"the quick brown fox jumps over "[(at * 7 + seed) % 31])
        .collect()
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// Members of every kind a set cuts: noise long enough to span many volumes
/// whether it is stored or not, text that codes small, short members that
/// share a volume, and an empty one.
fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b"long.bin".to_vec(), noise(64 * 1024, 7)),
        (b"short.txt".to_vec(), text(300, 3)),
        (b"empty".to_vec(), Vec::new()),
        (b"text.txt".to_vec(), text(40 * 1024, 0)),
        (b"tail.txt".to_vec(), text(5000, 11)),
    ]
}

#[derive(Clone, Copy, Debug)]
struct Case {
    level: u8,
    solid: bool,
    password: bool,
    header_encryption: bool,
    blake2sp: bool,
    recovery: Option<u64>,
}

impl Case {
    fn options(self) -> WriterOptions {
        let mut features = if self.level == 0 {
            FeatureSet::store_only()
        } else {
            FeatureSet::default()
        };
        features.solid = self.solid;
        features.header_encryption = self.header_encryption;
        features.blake2sp = self.blake2sp;
        WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(self.level)
    }

    fn entries(self) -> Vec<ArchiveEntry> {
        members()
            .into_iter()
            .map(|(name, data)| {
                let entry = ArchiveEntry::new(name, EntrySource::from_bytes(data));
                if self.password {
                    entry.with_password(b"secret".to_vec())
                } else {
                    entry
                }
            })
            .collect()
    }

    fn write(
        self,
        sink: &mut dyn VolumeSink,
        resources: &WriterResources,
        volume_size: u64,
    ) -> crate::Result<()> {
        seeded(|| {
            write_streaming_volumes_to(
                &self.entries(),
                self.options(),
                ArchiveExtras::default().with_recovery_percent(self.recovery),
                volume_size,
                sink,
                resources,
            )
        })
    }
}

fn seeded<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(feature = "encryption")]
    return crate::entropy::seeded::with(run);
    #[cfg(not(feature = "encryption"))]
    run()
}

fn cases() -> Vec<Case> {
    let plain = Case {
        level: 0,
        solid: false,
        password: false,
        header_encryption: false,
        blake2sp: false,
        recovery: None,
    };
    let mut cases = vec![
        plain,
        Case {
            blake2sp: true,
            ..plain
        },
        Case { level: 3, ..plain },
        Case {
            level: 3,
            solid: true,
            ..plain
        },
        Case {
            level: 1,
            blake2sp: true,
            ..plain
        },
    ];
    if cfg!(feature = "encryption") {
        cases.extend([
            Case {
                password: true,
                ..plain
            },
            Case {
                level: 3,
                password: true,
                blake2sp: true,
                ..plain
            },
            Case {
                password: true,
                header_encryption: true,
                ..plain
            },
            Case {
                level: 3,
                solid: true,
                password: true,
                header_encryption: true,
                ..plain
            },
        ]);
    }
    if cfg!(feature = "recovery") {
        cases.extend([
            Case {
                recovery: Some(5),
                ..plain
            },
            Case {
                level: 3,
                blake2sp: true,
                recovery: Some(10),
                ..plain
            },
        ]);
        if cfg!(feature = "encryption") {
            cases.push(Case {
                password: true,
                header_encryption: true,
                recovery: Some(5),
                ..plain
            });
        }
    }
    cases
}

fn read_back(case: Case, volumes: &[Vec<u8>]) {
    let password = case.password.then_some(b"secret".as_slice());
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| {
            crate::rar50::Archive::parse_owned_with_password(volume.clone(), password).unwrap()
        })
        .collect();
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    };
    let extracted = Arc::new(Mutex::new(Vec::new()));
    crate::rar50::extract_volumes_to(&archives, options, |meta| {
        let file = Arc::new(Mutex::new((meta.name.clone(), Vec::new())));
        extracted.lock().unwrap().push(file.clone());
        Ok(Box::new(Shared(file)))
    })
    .unwrap();
    let extracted: Vec<_> = extracted
        .lock()
        .unwrap()
        .iter()
        .map(|file| file.lock().unwrap().clone())
        .collect();
    assert_eq!(extracted, members(), "{case:?}");
}

struct Shared(Arc<Mutex<(Vec<u8>, Vec<u8>)>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().1.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn volumes_written_straight_out_match_spooled_ones() {
    let scratch = crate::scratch::case("volume-body-parity");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    for case in cases() {
        // 4 KiB volumes cut the long member across a dozen of them.
        for volume_size in [4096, 64 * 1024] {
            let mut seekable = CollectedVolumes::new();
            case.write(&mut seekable, &resources, volume_size).unwrap();
            let direct = seekable.take();
            let mut unseekable = Unseekable::default();
            case.write(&mut unseekable, &resources, volume_size)
                .unwrap();
            let spooled: Vec<_> = unseekable
                .volumes
                .iter()
                .map(|volume| volume.lock().unwrap().clone())
                .collect();
            assert_eq!(direct.len(), spooled.len(), "{case:?}, {volume_size}");
            if volume_size == 4096 {
                assert!(direct.len() > 12, "{case:?}: {} volumes", direct.len());
            }
            for (index, (direct, spooled)) in direct.iter().zip(&spooled).enumerate() {
                assert!(
                    direct == spooled,
                    "{case:?}, {volume_size}: volume {index} differs"
                );
                assert!(direct.len() as u64 <= volume_size);
            }
            read_back(case, &direct);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }
}

/// A set of stored members goes from its sources to its volumes without
/// touching scratch storage, encrypted or not, unless a volume has to be
/// spooled.
#[test]
fn stored_volumes_written_straight_out_need_no_spool() {
    let scratch = crate::scratch::case("volume-body-no-spool");
    let resources = WriterResources::default()
        .with_temp_dir(&*scratch)
        .with_max_spool_bytes(0);
    let stored = cases()[1];
    let mut cases = vec![stored];
    if cfg!(feature = "encryption") {
        cases.push(Case {
            password: true,
            ..stored
        });
    }
    for case in cases {
        let mut seekable = CollectedVolumes::new();
        case.write(&mut seekable, &resources, 4096).unwrap();
        read_back(case, &seekable.take());
        let refused = case
            .write(&mut Unseekable::default(), &resources, 4096)
            .unwrap_err();
        assert_eq!(refused.kind(), crate::ErrorKind::ResourceLimit, "{refused}");
    }
}

/// Counts the bytes that reach the first volume, through an output that seeks.
struct FirstVolumeWatched {
    collected: CollectedVolumes,
    first_volume_bytes: Arc<AtomicUsize>,
}

struct Watched {
    inner: Box<dyn VolumeOutput>,
    seen: Option<Arc<AtomicUsize>>,
}

impl Write for Watched {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        if let Some(seen) = &self.seen {
            seen.fetch_add(written, Ordering::SeqCst);
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for Watched {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

impl VolumeSink for FirstVolumeWatched {
    fn start_volume(&mut self, index: u64) -> crate::Result<Box<dyn VolumeOutput>> {
        Ok(Box::new(Watched {
            inner: self.collected.start_volume(index)?,
            seen: (index == 0).then(|| self.first_volume_bytes.clone()),
        }))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> crate::Result<()> {
        self.collected.finish_volume(index, len)
    }
}

/// Enough members that two threads and a small dictionary pack them in
/// several windows. The last one's source records how many bytes the first
/// volume held when it was opened.
fn many_members(
    password: bool,
    first_volume_bytes: &Arc<AtomicUsize>,
) -> (Vec<ArchiveEntry>, Arc<OnceLock<usize>>) {
    let count = 200;
    let at_last_open = Arc::new(OnceLock::new());
    let entries = (0..count)
        .map(|index| {
            let data = if index % 7 == 0 {
                noise(4096, index as u32)
            } else {
                text(16 * 1024, index)
            };
            let source = if index + 1 == count {
                let (seen, at) = (first_volume_bytes.clone(), at_last_open.clone());
                EntrySource::from_opener(data.len() as u64, move || {
                    at.get_or_init(|| seen.load(Ordering::SeqCst));
                    Ok(Box::new(std::io::Cursor::new(data.clone())))
                })
            } else {
                EntrySource::from_bytes(data)
            };
            let entry = ArchiveEntry::new(format!("member{index:04}").into_bytes(), source);
            if password {
                entry.with_password(b"secret".to_vec())
            } else {
                entry
            }
        })
        .collect();
    (entries, at_last_open)
}

fn many_member_options(level: u8, solid: bool, header_encryption: bool) -> WriterOptions {
    let mut features = if level == 0 {
        FeatureSet::store_only()
    } else {
        FeatureSet::default()
    };
    features.solid = solid;
    features.header_encryption = header_encryption;
    WriterOptions::new(ArchiveVersion::Rar50, features)
        .with_compression_level(level)
        .with_dictionary_size(256 * 1024)
}

/// (level, solid, encrypted) for the many-member sets.
fn many_member_cases() -> Vec<(u8, bool, bool)> {
    let mut cases = vec![(3, false, false), (3, true, false), (0, false, false)];
    if cfg!(feature = "encryption") {
        cases.extend([(3, false, true), (0, false, true)]);
    }
    cases
}

fn write_many(
    threads: usize,
    entries: &[ArchiveEntry],
    options: WriterOptions,
    sink: &mut (dyn VolumeSink + Send),
    resources: &WriterResources,
) {
    let write = || {
        seeded(|| {
            write_streaming_volumes_to(
                entries,
                options,
                ArchiveExtras::default(),
                16 * 1024,
                sink,
                resources,
            )
        })
    };
    #[cfg(feature = "parallel")]
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(write)
        .unwrap();
    #[cfg(not(feature = "parallel"))]
    {
        let _ = threads;
        let mut write = write;
        write().unwrap();
    }
}

#[test]
fn the_first_volume_is_written_before_the_last_member_is_packed() {
    let scratch = crate::scratch::case("volume-first-before-last");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    for (level, solid, encrypted) in many_member_cases() {
        let first_volume_bytes = Arc::new(AtomicUsize::new(0));
        let (entries, at_last_open) = many_members(encrypted, &first_volume_bytes);
        let options = many_member_options(level, solid, encrypted);
        let mut sink = FirstVolumeWatched {
            collected: CollectedVolumes::new(),
            first_volume_bytes: first_volume_bytes.clone(),
        };
        write_many(2, &entries, options, &mut sink, &resources);
        let at_last_open = *at_last_open.get().unwrap();
        assert!(
            at_last_open > 0,
            "level {level}, solid {solid}, encrypted {encrypted}: nothing reached the first volume before the last member was opened"
        );
        let volumes = sink.collected.take();
        assert!(volumes.len() > 2);
        let password = encrypted.then_some(b"secret".as_slice());
        let archives: Vec<_> = volumes
            .into_iter()
            .map(|volume| {
                crate::rar50::Archive::parse_owned_with_password(volume, password).unwrap()
            })
            .collect();
        let options = match password {
            Some(password) => ArchiveReadOptions::with_password(password),
            None => ArchiveReadOptions::new(),
        };
        let extracted = Arc::new(AtomicUsize::new(0));
        crate::rar50::extract_volumes_to(&archives, options, |_| {
            extracted.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(std::io::sink()))
        })
        .unwrap();
        assert_eq!(extracted.load(Ordering::SeqCst), entries.len());
    }
}

#[test]
fn a_volume_set_does_not_depend_on_the_thread_count() {
    let scratch = crate::scratch::case("volume-thread-count");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    for (level, solid, encrypted) in many_member_cases() {
        let mut first = None;
        for threads in [1, 2, 8] {
            let (entries, _) = many_members(encrypted, &Arc::new(AtomicUsize::new(0)));
            let mut sink = CollectedVolumes::new();
            let options = many_member_options(level, solid, encrypted);
            write_many(threads, &entries, options, &mut sink, &resources);
            let volumes = sink.take();
            match &first {
                None => first = Some(volumes),
                Some(first) => assert!(
                    *first == volumes,
                    "level {level}, solid {solid}, encrypted {encrypted}: {threads} threads wrote another set"
                ),
            }
        }
    }
}

/// Members above this are packed straight into the volumes in these tests.
const ABOVE: u64 = 256 * 1024;

/// Large members of every kind a set packs in place: text that packs small,
/// noise that is stored over its attempt, and small members around them.
fn large_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b"head.txt".to_vec(), text(3000, 5)),
        (b"big.txt".to_vec(), text(600 * 1024, 1)),
        (b"big.bin".to_vec(), noise(300 * 1024, 9)),
        (b"mid.txt".to_vec(), text(20 * 1024, 2)),
        (b"last.txt".to_vec(), text(400 * 1024, 4)),
    ]
}

fn large_cases() -> Vec<Case> {
    let packed = Case {
        level: 3,
        solid: false,
        password: false,
        header_encryption: false,
        blake2sp: false,
        recovery: None,
    };
    let mut cases = vec![
        packed,
        Case {
            solid: true,
            ..packed
        },
        Case {
            level: 1,
            blake2sp: true,
            ..packed
        },
    ];
    if cfg!(feature = "encryption") {
        cases.extend([
            Case {
                password: true,
                ..packed
            },
            Case {
                password: true,
                header_encryption: true,
                blake2sp: true,
                ..packed
            },
        ]);
    }
    if cfg!(feature = "recovery") {
        cases.push(Case {
            recovery: Some(5),
            ..packed
        });
        if cfg!(feature = "encryption") {
            cases.push(Case {
                solid: true,
                password: true,
                header_encryption: true,
                recovery: Some(3),
                ..packed
            });
        }
    }
    cases
}

fn large_entries(case: Case) -> Vec<ArchiveEntry> {
    large_members()
        .into_iter()
        .map(|(name, data)| {
            let entry = ArchiveEntry::new(name, EntrySource::from_bytes(data));
            if case.password {
                entry.with_password(b"secret".to_vec())
            } else {
                entry
            }
        })
        .collect()
}

fn write_large(
    case: Case,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    volume_size: u64,
    stream_above: u64,
) -> crate::Result<()> {
    seeded(|| {
        super::write_volumes_above(
            &large_entries(case),
            case.options(),
            ArchiveExtras::default().with_recovery_percent(case.recovery),
            volume_size,
            sink,
            resources,
            None,
            stream_above,
        )
    })
}

fn extract_large(case: Case, volumes: &[Vec<u8>]) {
    let password = case.password.then_some(b"secret".as_slice());
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| {
            crate::rar50::Archive::parse_owned_with_password(volume.clone(), password).unwrap()
        })
        .collect();
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    };
    let extracted = Arc::new(Mutex::new(Vec::new()));
    crate::rar50::extract_volumes_to(&archives, options, |meta| {
        let file = Arc::new(Mutex::new((meta.name.clone(), Vec::new())));
        extracted.lock().unwrap().push(file.clone());
        Ok(Box::new(Shared(file)))
    })
    .unwrap();
    let extracted: Vec<_> = extracted
        .lock()
        .unwrap()
        .iter()
        .map(|file| file.lock().unwrap().clone())
        .collect();
    assert!(extracted == large_members(), "{case:?}");
}

fn unseekable_volumes(sink: &Unseekable) -> Vec<Vec<u8>> {
    sink.volumes
        .iter()
        .map(|volume| volume.lock().unwrap().clone())
        .collect()
}

/// A large member packed straight into the volumes makes the set a spooled
/// one does, whether it ends inside a volume, spans a few, or spans more than
/// can be held open while it may still be stored over its attempt.
#[test]
fn large_members_packed_into_the_volumes_match_spooled_ones() {
    let scratch = crate::scratch::case("volume-in-place-parity");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    for case in large_cases() {
        for volume_size in [4096, 48 * 1024, 2 * 1024 * 1024] {
            let mut spooled = CollectedVolumes::new();
            write_large(case, &mut spooled, &resources, volume_size, u64::MAX).unwrap();
            let spooled = spooled.take();
            let mut packed = CollectedVolumes::new();
            write_large(case, &mut packed, &resources, volume_size, ABOVE).unwrap();
            let packed = packed.take();
            let mut unseekable = Unseekable::default();
            write_large(case, &mut unseekable, &resources, volume_size, ABOVE).unwrap();
            let unseekable = unseekable_volumes(&unseekable);
            assert_eq!(packed.len(), spooled.len(), "{case:?}, {volume_size}");
            for (index, (packed, spooled)) in packed.iter().zip(&spooled).enumerate() {
                assert!(
                    packed == spooled,
                    "{case:?}, {volume_size}: volume {index} differs"
                );
            }
            assert!(unseekable == spooled, "{case:?}, {volume_size}");
            extract_large(case, &packed);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }
}

/// Large members go into seekable volumes without passing through scratch
/// storage, recovery record and all, where volumes that cannot seek spool them.
#[test]
fn large_members_packed_into_the_volumes_need_no_spool() {
    let scratch = crate::scratch::case("volume-in-place-no-spool");
    let resources = WriterResources::default()
        .with_temp_dir(&*scratch)
        .with_max_spool_bytes(0);
    let in_place = large_cases()
        .into_iter()
        .filter(|case| !case.solid && !case.header_encryption);
    for case in in_place {
        // Only large members, as smaller ones are spooled once packed.
        let entries: Vec<_> = large_entries(case)
            .into_iter()
            .filter(|entry| entry.source.len().unwrap() > ABOVE)
            .collect();
        let write = |sink: &mut dyn VolumeSink| {
            seeded(|| {
                super::write_volumes_above(
                    &entries,
                    case.options(),
                    ArchiveExtras::default().with_recovery_percent(case.recovery),
                    48 * 1024,
                    sink,
                    &resources,
                    None,
                    ABOVE,
                )
            })
        };
        let mut packed = CollectedVolumes::new();
        write(&mut packed).unwrap_or_else(|error| panic!("{case:?}: {error}"));
        assert!(packed.take().len() > 4, "{case:?}");
        let refused = write(&mut Unseekable::default()).unwrap_err();
        assert_eq!(refused.kind(), crate::ErrorKind::ResourceLimit, "{refused}");
    }
}

/// With a recovery record, a seekable volume's record is built from what was
/// written to it, so no volume is spooled.
#[test]
fn recovery_volumes_written_straight_out_need_no_spool() {
    let scratch = crate::scratch::case("volume-recovery-no-spool");
    let resources = WriterResources::default()
        .with_temp_dir(&*scratch)
        .with_max_spool_bytes(0);
    let stored = cases()
        .into_iter()
        .filter(|case| case.level == 0 && case.recovery.is_some());
    let mut tried = 0;
    for case in stored {
        for volume_size in [4096, 64 * 1024] {
            let mut seekable = CollectedVolumes::new();
            case.write(&mut seekable, &resources, volume_size).unwrap();
            read_back(case, &seekable.take());
        }
        let refused = case
            .write(&mut Unseekable::default(), &resources, 4096)
            .unwrap_err();
        assert_eq!(refused.kind(), crate::ErrorKind::ResourceLimit, "{refused}");
        tried += 1;
    }
    assert_eq!(tried > 0, cfg!(feature = "recovery"));
}

#[test]
fn large_members_packed_into_the_volumes_do_not_depend_on_the_thread_count() {
    let scratch = crate::scratch::case("volume-in-place-threads");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    for case in large_cases().into_iter().take(2) {
        let mut first = None;
        for threads in [1, 2, 8] {
            let mut sink = CollectedVolumes::new();
            let write = || write_large(case, &mut sink, &resources, 48 * 1024, ABOVE);
            #[cfg(feature = "parallel")]
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(write)
                .unwrap();
            #[cfg(not(feature = "parallel"))]
            {
                let _ = threads;
                let mut write = write;
                write().unwrap();
            }
            let volumes = sink.take();
            match &first {
                None => first = Some(volumes),
                Some(first) => assert!(*first == volumes, "{case:?}: {threads} threads"),
            }
        }
    }
}

/// Volume sizes a byte apart move where a large member ends against the
/// edge of a volume: inside the bytes it holds back, just short of them, and
/// where its last fragment cannot start in the volume at all. Each lands where
/// a spooled member does.
#[test]
fn large_members_ending_at_a_volume_edge_match_spooled_ones() {
    let scratch = crate::scratch::case("volume-in-place-edges");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    let entries: Vec<_> = [
        noise(300 * 1024, 3),
        text(200, 1),
        text(280 * 1024, 2),
        noise(270 * 1024, 8),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, data)| {
        ArchiveEntry::new(
            format!("m{index}").into_bytes(),
            EntrySource::from_bytes(data),
        )
    })
    .collect();
    let options =
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default()).with_compression_level(1);
    let mut recoveries = vec![None];
    if cfg!(feature = "recovery") {
        recoveries.push(Some(5));
    }
    for recovery in recoveries {
        for volume_size in 2016..2032 {
            let write = |sink: &mut dyn VolumeSink, above| {
                seeded(|| {
                    super::write_volumes_above(
                        &entries,
                        options,
                        ArchiveExtras::default().with_recovery_percent(recovery),
                        volume_size,
                        sink,
                        &resources,
                        None,
                        above,
                    )
                })
            };
            let mut spooled = CollectedVolumes::new();
            let mut packed = CollectedVolumes::new();
            match (write(&mut spooled, u64::MAX), write(&mut packed, ABOVE)) {
                (Ok(()), Ok(())) => assert!(
                    spooled.take() == packed.take(),
                    "{recovery:?}, {volume_size}"
                ),
                (spooled, packed) => panic!("{recovery:?}, {volume_size}: {spooled:?} {packed:?}"),
            }
        }
    }
}

#[cfg(feature = "recovery")]
fn extracted(volumes: &[Vec<u8>], password: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| {
            crate::rar50::Archive::parse_owned_with_password(volume.clone(), password).unwrap()
        })
        .collect();
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    };
    let extracted = Arc::new(Mutex::new(Vec::new()));
    crate::rar50::extract_volumes_to(&archives, options, |meta| {
        let file = Arc::new(Mutex::new((meta.name.clone(), Vec::new())));
        extracted.lock().unwrap().push(file.clone());
        Ok(Box::new(Shared(file)))
    })
    .unwrap();
    let extracted = extracted.lock().unwrap();
    extracted
        .iter()
        .map(|file| file.lock().unwrap().clone())
        .collect()
}

/// Members a few volumes of 2 to 4 KiB hold, noise and text by turns.
#[cfg(feature = "recovery")]
fn small_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..6)
        .map(|index| {
            let len = 700 + index * 1300;
            let data = if index % 2 == 0 {
                noise(len, index as u32)
            } else {
                text(len, index)
            };
            (format!("m{index}").into_bytes(), data)
        })
        .collect()
}

/// Writes `members` as `case` into volumes of `volume_size`, and checks none
/// comes out longer.
#[cfg(feature = "recovery")]
fn write_small(
    members: &[(Vec<u8>, Vec<u8>)],
    case: Case,
    volume_size: u64,
    resources: &WriterResources,
) -> crate::Result<Vec<Vec<u8>>> {
    let entries: Vec<_> = members
        .iter()
        .map(|(name, data)| {
            let entry = ArchiveEntry::new(name.clone(), EntrySource::from_bytes(data.clone()));
            if case.password {
                entry.with_password(b"secret".to_vec())
            } else {
                entry
            }
        })
        .collect();
    let mut sink = CollectedVolumes::new();
    seeded(|| {
        write_streaming_volumes_to(
            &entries,
            case.options(),
            ArchiveExtras::default().with_recovery_percent(case.recovery),
            volume_size,
            &mut sink,
            resources,
        )
    })?;
    let volumes = sink.take();
    for (index, volume) in volumes.iter().enumerate() {
        assert!(
            volume.len() as u64 <= volume_size,
            "{case:?}, {volume_size}: volume {index} is {} bytes",
            volume.len()
        );
    }
    Ok(volumes)
}

#[cfg(feature = "recovery")]
const STORED_WITH_RECOVERY: Case = Case {
    level: 0,
    solid: false,
    password: false,
    header_encryption: false,
    blake2sp: false,
    recovery: Some(3),
};

/// With a recovery record, a small volume's overhead does not only grow with
/// its body: below about 200 KiB the record over a shorter body can be the
/// longer one. These sizes put a member's end, the set's last one among
/// them, where the volume would come out too long, or a member's next
/// fragment back in the volume it was split from.
#[cfg(feature = "recovery")]
#[test]
fn small_recovery_volumes_fit_where_a_shorter_body_has_a_longer_record() {
    let scratch = crate::scratch::case("volume-recovery-small-edges");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    let packed = Case {
        level: 1,
        recovery: Some(10),
        ..STORED_WITH_RECOVERY
    };
    for (case, volume_size) in [
        (STORED_WITH_RECOVERY, 2078),
        (STORED_WITH_RECOVERY, 2891),
        (STORED_WITH_RECOVERY, 2913),
        (packed, 2000),
        (packed, 2991),
    ] {
        let volumes = write_small(&small_members(), case, volume_size, &resources)
            .unwrap_or_else(|error| panic!("{case:?}, {volume_size}: {error}"));
        assert!(
            extracted(&volumes, None) == small_members(),
            "{case:?}, {volume_size}"
        );
    }
}

/// Every volume size from 2000 to 4200 bytes, with members ending at every
/// point of such volumes: each volume comes in within the volume size, or the
/// set is refused as too small to hold a member header.
#[cfg(feature = "recovery")]
#[test]
fn small_recovery_volumes_stay_within_the_volume_size() {
    let scratch = crate::scratch::case("volume-recovery-small");
    let resources = WriterResources::default().with_temp_dir(&*scratch);
    let mixed = small_members();
    let short_last = vec![
        (b"a".to_vec(), noise(3 * 1024, 5)),
        (b"b".to_vec(), text(200, 1)),
        (b"c".to_vec(), Vec::new()),
        (b"d".to_vec(), noise(5 * 1024 + 17, 6)),
        (b"e".to_vec(), text(40, 2)),
    ];
    let stored = STORED_WITH_RECOVERY;
    let mut runs = vec![
        (&mixed, stored),
        (
            &mixed,
            Case {
                level: 1,
                recovery: Some(10),
                ..stored
            },
        ),
        (
            &short_last,
            Case {
                level: 3,
                blake2sp: true,
                recovery: Some(5),
                ..stored
            },
        ),
    ];
    if cfg!(feature = "encryption") {
        runs.push((
            &short_last,
            Case {
                password: true,
                header_encryption: true,
                ..stored
            },
        ));
    }
    let mut written = 0;
    for (members, case) in runs {
        for volume_size in 2000..4200 {
            let volumes = match write_small(members, case, volume_size, &resources) {
                Ok(volumes) => volumes,
                Err(error) => {
                    assert_eq!(
                        error.to_string(),
                        "invalid argument: RAR 5 volume size is too small to hold a member header",
                        "{case:?}, {volume_size}"
                    );
                    continue;
                }
            };
            // Extracting every set would double the test's time, and sets a
            // few bytes apart are cut much alike.
            if volume_size % 7 == 0 {
                let password = case.password.then_some(b"secret".as_slice());
                assert!(
                    extracted(&volumes, password) == *members,
                    "{case:?}, {volume_size}"
                );
            }
            written += 1;
        }
    }
    assert!(written > 0);
}
