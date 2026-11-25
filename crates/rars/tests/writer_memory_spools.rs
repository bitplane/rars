#![cfg(feature = "write")]
//! Spools that stay small are held in memory, charged to the writer's budget,
//! and make no temporary files. Large ones still go to disk.

#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveReader, ArchiveVersion, Builder, WriteProgressEvent, WriterResources};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// An output that notes whether the temp directory held anything at each write.
struct Watching {
    out: Vec<u8>,
    dir: PathBuf,
    saw_file: Arc<AtomicBool>,
}

impl Write for Watching {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        note_files(&self.dir, &self.saw_file);
        self.out.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn note_files(dir: &Path, saw_file: &AtomicBool) {
    if std::fs::read_dir(dir).unwrap().next().is_some() {
        saw_file.store(true, Ordering::Relaxed);
    }
}

/// Writes `builder` with spools in `dir`, watching it from the output and from
/// progress. Returns the archive and whether any spool file appeared.
fn write_watched(builder: &Builder, resources: &WriterResources, dir: &Path) -> (Vec<u8>, bool) {
    let saw_file = Arc::new(AtomicBool::new(false));
    let progress = {
        let dir = dir.to_path_buf();
        let saw_file = saw_file.clone();
        move |_: WriteProgressEvent<'_>| note_files(&dir, &saw_file)
    };
    let mut output = Watching {
        out: Vec::new(),
        dir: dir.to_path_buf(),
        saw_file: saw_file.clone(),
    };
    builder
        .write_to(&mut output, resources, Some(&progress))
        .unwrap();
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
    (output.out, saw_file.load(Ordering::Relaxed))
}

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

/// Packs to about half its size, so the packed member is spooled.
fn nibbles(len: usize, seed: u32) -> Vec<u8> {
    noise(len, seed)
        .into_iter()
        .map(|byte| b'a' + (byte & 15))
        .collect()
}

fn small_members(builder: &mut Builder) {
    builder
        .add_bytes(
            b"text".to_vec(),
            b"small text member ".repeat(4096),
            None,
            None,
        )
        .unwrap();
    builder
        .add_bytes(b"noise".to_vec(), noise(256 * 1024, 7), None, None)
        .unwrap();
    builder
        .add_bytes(b"zeros".to_vec(), vec![0; 512 * 1024], None, None)
        .unwrap();
}

#[test]
fn a_write_whose_spools_stay_small_creates_no_temp_files() {
    let root = scratch::case("memory-spools-small");
    let resources = WriterResources::default().with_temp_dir(&*root);
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for (stored, solid, password, recovery) in [
            (false, false, None, None),
            (true, false, None, None),
            (false, true, None, None),
            (false, false, Some(b"secret".to_vec()), None),
            (false, false, None, Some(10)),
        ]
        .into_iter()
        .filter(|row| cfg!(feature = "encryption") || row.2.is_none())
        .filter(|row| cfg!(feature = "recovery") || row.3.is_none())
        {
            let mut builder = Builder::new(target)
                .store(stored)
                .solid(solid)
                .password(password.clone())
                .recovery_percent(recovery);
            small_members(&mut builder);
            let (archive, saw_file) = write_watched(&builder, &resources, &root);
            let row = format!("{target:?} stored={stored} solid={solid} recovery={recovery:?}");
            assert!(!saw_file, "{row}: a spool went to disk");
            ArchiveReader::read_owned(archive)
                .unwrap()
                .test(password.as_deref())
                .unwrap_or_else(|error| panic!("{row}: {error}"));
        }
    }
}

#[test]
fn a_spool_past_the_threshold_goes_to_disk() {
    let root = scratch::case("memory-spools-large");
    let resources = WriterResources::default().with_temp_dir(&*root);
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"large".to_vec(), nibbles(12 * 1024 * 1024, 11), None, None)
        .unwrap();
    let (archive, saw_file) = write_watched(&builder, &resources, &root);
    assert!(saw_file, "a 6 MiB member stayed in memory");
    ArchiveReader::read_owned(archive)
        .unwrap()
        .test(None)
        .unwrap();
}

#[test]
fn spools_in_memory_write_the_archive_spools_on_disk_do() {
    // A managed allocation ceiling starts every spool on disk.
    let root = scratch::case("memory-spools-parity");
    let in_memory = WriterResources::default().with_temp_dir(&*root);
    let on_disk = in_memory.clone().with_max_memory_bytes(u64::MAX / 2);
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for solid in [false, true] {
            let mut builder = Builder::new(target).solid(solid);
            small_members(&mut builder);
            let (from_memory, _) = write_watched(&builder, &in_memory, &root);
            let (from_disk, saw_file) = write_watched(&builder, &on_disk, &root);
            assert!(saw_file, "{target:?} solid={solid}: no spool went to disk");
            assert!(
                from_memory == from_disk,
                "{target:?} solid={solid}: the archive changed"
            );
        }
    }
}

#[test]
fn a_tight_budget_sends_spools_to_disk_and_stays_within_it() {
    let root = scratch::case("memory-spools-tight");
    let mut builder = Builder::new(ArchiveVersion::Rar50).compression_level(Some(1));
    for seed in 1..=4 {
        let name = format!("member{seed}").into_bytes();
        builder
            .add_bytes(name, nibbles(1024 * 1024, seed), None, None)
            .unwrap();
    }
    // Room for one job, which needs nearly all of it, and little beside: the
    // next job's admission moves the last member's spool to disk.
    let limit = 69 * 1024 * 1024;
    let tight = WriterResources::new(limit).with_temp_dir(&*root);
    let (archive, saw_file) = write_watched(&builder, &tight, &root);
    assert!(saw_file, "every spool stayed in memory");
    assert!(tight.workspace_peak() <= limit);
    let on_disk = WriterResources::new(limit)
        .with_temp_dir(&*root)
        .with_max_memory_bytes(u64::MAX / 2);
    let (expected, _) = write_watched(&builder, &on_disk, &root);
    assert!(archive == expected, "the archive changed");
    ArchiveReader::read_owned(archive)
        .unwrap()
        .test(None)
        .unwrap();
}

#[test]
fn volume_sets_spool_small_members_in_memory() {
    let root = scratch::case("memory-spools-volumes");
    let password = cfg!(feature = "encryption").then(|| b"secret".to_vec());
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .password(password)
        .volume_size(Some(200 * 1024));
    small_members(&mut builder);
    let in_memory = WriterResources::default().with_temp_dir(&*root);
    // A managed allocation ceiling starts every spool on disk.
    let on_disk = in_memory.clone().with_max_memory_bytes(u64::MAX / 2);
    for (resources, spools_on_disk) in [(in_memory, false), (on_disk, true)] {
        let saw_file = Arc::new(AtomicBool::new(false));
        let progress = {
            let dir = root.to_path_buf();
            let saw_file = saw_file.clone();
            move |_: WriteProgressEvent<'_>| note_files(&dir, &saw_file)
        };
        let volumes = builder
            .build_volumes_with_resources(&resources, Some(&progress))
            .unwrap();
        assert!(volumes.len() > 1);
        assert_eq!(saw_file.load(Ordering::Relaxed), spools_on_disk);
        assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
    }
}
