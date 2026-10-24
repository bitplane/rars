#![cfg(feature = "write")]

//! Managed-allocation correctness checks, deliberately independent of RSS and timing.
//! Inputs and the caller-owned output Vec are outside WriterResources' ledger.

#[path = "support/scratch.rs"]
mod scratch;

use rars::atomic64::AtomicU64;
use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{
    ArchiveReader, ArchiveVersion, Builder, EntrySource, ErrorKind, FeatureSet, WriteOperation,
    WriteProgress, WriteProgressEvent, WriterResources,
};
use std::sync::atomic::{AtomicBool, Ordering};

const KIB: usize = 1024;
const MIB: u64 = 1024 * 1024;
const MEMBER_SIZE: usize = 160 * KIB;
const SMALL_LIMIT: u64 = 96 * MIB;

#[derive(Clone, Copy, Debug)]
enum Data {
    Incompressible,
    Repetitive,
}

impl Data {
    fn bytes(self, size: usize) -> Vec<u8> {
        match self {
            Self::Incompressible => {
                let mut state = 0x2545_f491_4f6c_dd1du64;
                (0..size)
                    .map(|_| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        (state >> 33) as u8
                    })
                    .collect()
            }
            Self::Repetitive => b"bounded encoder memory; repeated payload\n"
                .iter()
                .copied()
                .cycle()
                .take(size)
                .collect(),
        }
    }
}

fn resources(root: &std::path::Path, limit: u64) -> WriterResources {
    WriterResources::new(512 * MIB)
        .with_temp_dir(root)
        .with_max_memory_bytes(limit)
}

struct Observe<'a> {
    resources: &'a WriterResources,
    peak: AtomicU64,
    advanced: AtomicBool,
}

impl<'a> Observe<'a> {
    fn new(resources: &'a WriterResources) -> Self {
        Self {
            resources,
            peak: AtomicU64::new(0),
            advanced: AtomicBool::new(false),
        }
    }
}

impl WriteProgress for Observe<'_> {
    fn report(&self, event: WriteProgressEvent<'_>) {
        let used = self.resources.managed_memory_in_use();
        assert!(used <= self.resources.max_memory_bytes().unwrap());
        self.peak.fetch_max(used, Ordering::Relaxed);
        if matches!(
            event,
            WriteProgressEvent::Advanced {
                operation: WriteOperation::Compression,
                completed_bytes: 1..,
                ..
            }
        ) {
            self.advanced.store(true, Ordering::Relaxed);
        }
    }
}

fn with_threads<T: Send>(threads: usize, run: impl FnOnce() -> T + Send) -> T {
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(run)
    }
    #[cfg(any(
        not(feature = "parallel"),
        all(target_arch = "wasm32", target_os = "unknown")
    ))]
    {
        assert_eq!(threads, 1);
        run()
    }
}

fn thread_counts() -> &'static [usize] {
    if cfg!(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    )) {
        &[1, 2]
    } else {
        &[1]
    }
}

fn assert_archive(bytes: &[u8], expected: &[u8], dictionary: Option<u64>, compressed: bool) {
    let archive = ArchiveReader::read(bytes).unwrap();
    archive.test(None).unwrap();
    for name in [b"first".as_slice(), b"second".as_slice()] {
        assert_eq!(archive.read_member(name, None).unwrap().unwrap(), expected);
    }
    let files: Vec<_> = archive.as_rar50().unwrap().files().collect();
    assert_eq!(files.len(), 2);
    for file in files {
        let info = file.decoded_compression_info().unwrap();
        if let Some(dictionary) = dictionary {
            assert_eq!(info.dictionary_size, dictionary);
        }
        if compressed {
            assert_ne!(
                info.method, 0,
                "repetitive fixture must exercise compression"
            );
        }
    }
}

#[test]
fn default_builder_and_explicit_dictionaries_fit_fixed_managed_ceilings() {
    let root = scratch::case("encoder-memory-matrix");
    // Every level and input kind runs with each dictionary and enabled thread
    // count. 160 KiB exceeds the 128 KiB ring; RAR7 also covers a fractional size.
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let dictionaries: &[Option<u64>] = if version == ArchiveVersion::Rar70 {
            &[
                None,
                Some(128 * KIB as u64),
                Some(192 * KIB as u64),
                Some(MIB),
            ]
        } else {
            &[None, Some(128 * KIB as u64), Some(MIB)]
        };
        for &dictionary in dictionaries {
            for level in [1, 3, 5] {
                for kind in [Data::Incompressible, Data::Repetitive] {
                    let data = kind.bytes(MEMBER_SIZE);
                    let mut serial = None;
                    for &threads in thread_counts() {
                        let resources = resources(&root, SMALL_LIMIT);
                        let observe = Observe::new(&resources);
                        let mut bytes = Vec::new();
                        with_threads(threads, || {
                            if let Some(dictionary) = dictionary {
                                let entries = ["first", "second"].map(|name| {
                                    ArchiveEntry::new(name, EntrySource::from_bytes(data.clone()))
                                });
                                rar50::write_streaming_archive_with_progress(
                                    &entries,
                                    WriterOptions::new(version, FeatureSet::store_only())
                                        .with_compression_level(level)
                                        .with_dictionary_size(dictionary),
                                    ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
                                    &resources,
                                    Some(&observe),
                                    &mut bytes,
                                )
                                .unwrap();
                            } else {
                                let mut builder =
                                    Builder::new(version).compression_level(Some(level));
                                for name in ["first", "second"] {
                                    builder
                                        .add_bytes(
                                            name.as_bytes().to_vec(),
                                            data.clone(),
                                            None,
                                            None,
                                        )
                                        .unwrap();
                                }
                                builder
                                    .write_to(&mut bytes, &resources, Some(&observe))
                                    .unwrap();
                            }
                        });
                        assert!(observe.advanced.load(Ordering::Relaxed));
                        assert!(observe.peak.load(Ordering::Relaxed) > 0);
                        assert_eq!(resources.managed_memory_in_use(), 0);
                        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
                        assert_archive(
                            &bytes,
                            &data,
                            Some(dictionary.unwrap_or(256 * KIB as u64)),
                            matches!(kind, Data::Repetitive),
                        );
                        if let Some(serial) = &serial {
                            assert_eq!(
                                &bytes, serial,
                                "{version:?} {dictionary:?} {level} {kind:?}"
                            );
                        } else {
                            serial = Some(bytes);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn solid_multirun_history_fits_fixed_ceiling_and_extracts() {
    let root = scratch::case("encoder-memory-packed-history");
    // Two 1 MiB members form two 1 MiB runs.
    // The latter has nonempty 1 MiB history and 2 MiB combined input, so
    // level 3 selects the promoted packed collector (1 MiB <= combined <= 2D).
    const SIZE: usize = 1024 * KIB;
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for kind in [Data::Incompressible, Data::Repetitive] {
            let data = kind.bytes(SIZE);
            let mut serial = None;
            for &threads in thread_counts() {
                let resources = resources(&root, 448 * MIB);
                let observe = Observe::new(&resources);
                let entries = ["first", "second"]
                    .map(|name| ArchiveEntry::new(name, EntrySource::from_bytes(data.clone())));
                let mut features = FeatureSet::store_only();
                features.solid = true;
                let mut bytes = Vec::new();
                with_threads(threads, || {
                    rar50::write_streaming_archive_with_progress(
                        &entries,
                        WriterOptions::new(version, features)
                            .with_compression_level(3)
                            .with_dictionary_size(MIB),
                        ArchiveExtras::default(),
                        &resources,
                        Some(&observe),
                        &mut bytes,
                    )
                })
                .unwrap();
                assert!(observe.advanced.load(Ordering::Relaxed));
                assert!(observe.peak.load(Ordering::Relaxed) > 0);
                assert_eq!(resources.managed_memory_in_use(), 0);
                assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
                assert_archive(&bytes, &data, Some(MIB), true);
                if let Some(serial) = &serial {
                    assert_eq!(&bytes, serial);
                } else {
                    serial = Some(bytes);
                }
            }
        }
    }
}

#[test]
fn codec_refusal_and_spool_refusal_preserve_destination_and_release_capacity() {
    let root = scratch::case("encoder-memory-refusal");
    let path = root.join("archive.rar");
    let original = b"existing published archive";
    std::fs::write(&path, original).unwrap();
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let mut builder = Builder::new(version).compression_level(Some(3));
        builder
            .add_bytes(
                b"member".to_vec(),
                Data::Repetitive.bytes(MEMBER_SIZE),
                None,
                None,
            )
            .unwrap();
        // 1 MiB admits descriptors/headers but cannot admit the codec's worker.
        // A zero-byte spool limit instead refuses packed output after encoding.
        for (limit, spool_limit) in [(MIB, None), (SMALL_LIMIT, Some(0))] {
            let mut resources = resources(&root, limit);
            if let Some(spool_limit) = spool_limit {
                resources = resources.with_max_spool_bytes(spool_limit);
            }
            for _ in 0..2 {
                let observe = Observe::new(&resources);
                let error = builder
                    .write_to_path_with_resources(&path, &resources, Some(&observe))
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::ResourceLimit);
                if spool_limit.is_some() {
                    assert!(matches!(
                        error.root_cause(),
                        rars::Error::WriterSpoolLimitExceeded { limit: 0, .. }
                    ));
                    assert!(
                        observe.advanced.load(Ordering::Relaxed),
                        "refusal must follow codec work"
                    );
                } else {
                    assert!(
                        matches!(
                            error.root_cause(),
                            rars::Error::Codec(rars::codec::Error::WorkspaceLimitExceeded(_))
                        ),
                        "{error}"
                    );
                }
                assert_eq!(resources.managed_memory_in_use(), 0);
                assert_eq!(std::fs::read(&path).unwrap(), original);
                assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
                // Reuse the same quota group for an operation requiring neither
                // a codec nor a nonempty spool; stale reservations would fail.
                let empty = Builder::new(version).store(true);
                empty.write_to(&mut Vec::new(), &resources, None).unwrap();
                assert_eq!(resources.managed_memory_in_use(), 0);
            }
        }
    }
}

#[test]
fn cancellation_during_codec_work_cleans_up_and_allows_reuse() {
    struct CancelDuringEncoding<'a> {
        observe: Observe<'a>,
        cancelled: AtomicBool,
    }
    impl WriteProgress for CancelDuringEncoding<'_> {
        fn report(&self, event: WriteProgressEvent<'_>) {
            self.observe.report(event);
            if self.observe.advanced.load(Ordering::Relaxed) {
                self.cancelled.store(true, Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::Relaxed)
        }
    }
    let root = scratch::case("encoder-memory-cancel");
    let path = root.join("archive.rar");
    std::fs::write(&path, b"original").unwrap();
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let data = Data::Repetitive.bytes(MEMBER_SIZE);
        let mut builder = Builder::new(version).compression_level(Some(5));
        for name in ["first", "second"] {
            builder
                .add_bytes(name.as_bytes().to_vec(), data.clone(), None, None)
                .unwrap();
        }
        let resources = resources(&root, SMALL_LIMIT);
        for _ in 0..2 {
            let progress = CancelDuringEncoding {
                observe: Observe::new(&resources),
                cancelled: AtomicBool::new(false),
            };
            let error = builder
                .write_to_path_with_resources(&path, &resources, Some(&progress))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Cancelled);
            assert!(progress.observe.advanced.load(Ordering::Relaxed));
            assert_eq!(resources.managed_memory_in_use(), 0);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
            let mut bytes = Vec::new();
            builder.write_to(&mut bytes, &resources, None).unwrap();
            assert_eq!(resources.managed_memory_in_use(), 0);
            assert_archive(&bytes, &data, Some(256 * KIB as u64), true);
        }
    }
}

#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
#[test]
fn two_codec_workers_hold_admitted_capacity_concurrently() {
    use std::collections::HashSet;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    struct Rendezvous<'a> {
        observe: Observe<'a>,
        workers: Mutex<HashSet<std::thread::ThreadId>>,
        changed: Condvar,
        timed_out: AtomicBool,
    }
    impl WriteProgress for Rendezvous<'_> {
        fn report(&self, event: WriteProgressEvent<'_>) {
            self.observe.report(event);
            if matches!(
                event,
                WriteProgressEvent::EntryStarted {
                    operation: WriteOperation::Compression,
                    ..
                }
            ) {
                let mut workers = self.workers.lock().unwrap();
                workers.insert(std::thread::current().id());
                self.changed.notify_all();
                // A timeout only prevents a scheduling regression from hanging
                // the suite; elapsed time is never a performance assertion.
                let (workers, timeout) = self
                    .changed
                    .wait_timeout_while(workers, Duration::from_secs(10), |workers| {
                        workers.len() < 2
                    })
                    .unwrap();
                if timeout.timed_out() && workers.len() < 2 {
                    self.timed_out.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    let root = scratch::case("encoder-memory-two-workers");
    let resources = resources(&root, SMALL_LIMIT);
    let progress = Rendezvous {
        observe: Observe::new(&resources),
        workers: Mutex::new(HashSet::new()),
        changed: Condvar::new(),
        timed_out: AtomicBool::new(false),
    };
    let data = Data::Repetitive.bytes(MEMBER_SIZE);
    let mut builder = Builder::new(ArchiveVersion::Rar70).compression_level(Some(3));
    for name in ["first", "second"] {
        builder
            .add_bytes(name.as_bytes().to_vec(), data.clone(), None, None)
            .unwrap();
    }
    let mut bytes = Vec::new();
    with_threads(2, || {
        builder.write_to(&mut bytes, &resources, Some(&progress))
    })
    .unwrap();
    assert!(
        !progress.timed_out.load(Ordering::Relaxed),
        "two admitted workers did not rendezvous"
    );
    assert_eq!(progress.workers.lock().unwrap().len(), 2);
    assert!(progress.observe.peak.load(Ordering::Relaxed) > 0);
    assert_eq!(resources.managed_memory_in_use(), 0);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    assert_archive(&bytes, &data, Some(256 * KIB as u64), true);
}
