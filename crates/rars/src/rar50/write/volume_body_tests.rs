//! A volume written straight into its output matches one whose body is
//! spooled and copied in when the volume closes. An output that cannot seek
//! still takes the spooled route, so the two are compared byte for byte.

use super::{write_streaming_volumes_to, ArchiveEntry, ArchiveExtras, WriterOptions};
use crate::rar50::{CollectedVolumes, VolumeOutput, VolumeSink};
use crate::{ArchiveReadOptions, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

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
/// touching scratch storage, unless a volume has to be spooled.
#[test]
fn stored_volumes_written_straight_out_need_no_spool() {
    let scratch = crate::scratch::case("volume-body-no-spool");
    let resources = WriterResources::default()
        .with_temp_dir(&*scratch)
        .with_max_spool_bytes(0);
    let case = cases()[1];
    let mut seekable = CollectedVolumes::new();
    case.write(&mut seekable, &resources, 4096).unwrap();
    read_back(case, &seekable.take());
    let refused = case
        .write(&mut Unseekable::default(), &resources, 4096)
        .unwrap_err();
    assert_eq!(refused.kind(), crate::ErrorKind::ResourceLimit, "{refused}");
}
