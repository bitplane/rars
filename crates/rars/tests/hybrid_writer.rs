#![cfg(feature = "write")]

use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
use rars::{
    ArchiveVersion, EntrySource, FeatureSet, HybridOptions, HybridProfile, WriterResources,
};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn options(target: ArchiveVersion) -> WriterOptions {
    WriterOptions::new(target, FeatureSet::store_only())
        .with_compression_level(3)
        .with_dictionary_size(128 * 1024)
        .with_hybrid(
            HybridOptions::new(HybridProfile::Desktop)
                .with_variant(0)
                .unwrap(),
        )
}

fn contents(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    struct Output(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let archive = rars::rar50::Archive::parse(bytes).unwrap();
    let mut outputs = Vec::new();
    archive
        .extract_to(rars::ArchiveReadOptions::new(), |metadata| {
            let output = Arc::new(std::sync::Mutex::new(Vec::new()));
            outputs.push((metadata.name.clone(), output.clone()));
            Ok(Box::new(Output(output)))
        })
        .unwrap();
    outputs
        .into_iter()
        .map(|(name, bytes)| (name, Arc::try_unwrap(bytes).unwrap().into_inner().unwrap()))
        .collect()
}

#[test]
fn hybrid_captures_original_source_exactly_once() {
    let opens = Arc::new(AtomicUsize::new(0));
    let counter = opens.clone();
    let data = b"an exact snapshot and repeated snapshot".repeat(60);
    let snapshot = data.clone();
    let source = EntrySource::from_opener(data.len() as u64, move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Cursor::new(snapshot.clone())))
    });
    let archive = Rar50Writer::new(options(ArchiveVersion::Rar50))
        .entry(ArchiveEntry::new(b"one.txt".to_vec(), source))
        .finish()
        .unwrap();
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    assert_eq!(contents(&archive), vec![(b"one.txt".to_vec(), data)]);
}

#[test]
fn hybrid_continuation_roundtrips_across_decision_windows() {
    let data = b"0123456789abcdefghijklmnop".repeat(11_000);
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let archive = Rar50Writer::new(options(target))
            .entry(ArchiveEntry::new(
                b"long.bin".to_vec(),
                EntrySource::from_bytes(data.clone()),
            ))
            .finish()
            .unwrap();
        assert_eq!(
            contents(&archive),
            vec![(b"long.bin".to_vec(), data.clone())]
        );
    }
}

#[test]
fn hybrid_preserves_members_and_explicit_dictionary() {
    let data = b"independent duplicated content".repeat(90);
    let archive = Rar50Writer::new(options(ArchiveVersion::Rar70))
        .entry(ArchiveEntry::new(
            b"first".to_vec(),
            EntrySource::from_bytes(data.clone()),
        ))
        .entry(ArchiveEntry::new(
            b"second".to_vec(),
            EntrySource::from_bytes(data.clone()),
        ))
        .finish()
        .unwrap();
    assert_eq!(
        contents(&archive),
        vec![
            (b"first".to_vec(), data.clone()),
            (b"second".to_vec(), data)
        ]
    );
    let parsed = rars::rar50::Archive::parse(&archive).unwrap();
    for member in parsed.files() {
        assert!(member.redirection.is_none());
        assert_eq!(
            member.decoded_compression_info().unwrap().dictionary_size,
            128 * 1024
        );
    }
}

#[test]
fn hybrid_storage_refusal_never_publishes_an_archive() {
    let resources = WriterResources::default().with_max_spool_bytes(64);
    let mut output = Vec::new();
    let error = Rar50Writer::new(options(ArchiveVersion::Rar50))
        .entry(ArchiveEntry::new(
            b"large".to_vec(),
            EntrySource::from_bytes(vec![1u8; 1024]),
        ))
        .write_to(&mut output, &resources)
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
    assert!(output.is_empty());
}

#[test]
fn hybrid_rejects_changed_source_size_and_invalid_order_policy() {
    let source = EntrySource::from_opener(20, || Ok(Box::new(Cursor::new(vec![0u8; 19]))));
    let error = Rar50Writer::new(options(ArchiveVersion::Rar50))
        .entry(ArchiveEntry::new(b"changed".to_vec(), source))
        .finish()
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
    let invalid = HybridOptions::default().with_member_order_optimization(true);
    let error = Rar50Writer::new(options(ArchiveVersion::Rar50).with_hybrid(invalid))
        .entry(ArchiveEntry::new(
            b"file".to_vec(),
            EntrySource::from_bytes(vec![1u8]),
        ))
        .finish()
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
}

#[test]
fn hybrid_explicit_requests_are_validated_before_capture() {
    let opens = Arc::new(AtomicUsize::new(0));
    for (hybrid, filter) in [
        (
            HybridOptions::default()
                .with_variant(0)
                .unwrap()
                .with_archive_analysis(true)
                .with_member_order_optimization(true),
            rars::FilterPolicy::None,
        ),
        (
            HybridOptions::default().with_variant(0).unwrap(),
            rars::FilterPolicy::Auto,
        ),
        (
            HybridOptions::default(),
            rars::FilterPolicy::Explicit(rars::FilterSpec::range(rars::FilterKind::E8, 0..21)),
        ),
    ] {
        let counter = opens.clone();
        let source = EntrySource::from_opener(20, move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Cursor::new(vec![0u8; 20])))
        });
        let error = Rar50Writer::new(options(ArchiveVersion::Rar50).with_hybrid(hybrid))
            .entry(ArchiveEntry::new(b"file".to_vec(), source))
            .filter_policy(filter)
            .finish()
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
    }
    assert_eq!(opens.load(Ordering::SeqCst), 0);
}

#[test]
fn hybrid_controls_and_solid_joins_roundtrip() {
    for architecture in [
        rars::HybridArchitecture::Hybrid,
        rars::HybridArchitecture::Relationships,
        rars::HybridArchitecture::Streams,
    ] {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let hybrid = HybridOptions::default()
            .with_variant(0)
            .unwrap()
            .with_architecture(architecture);
        let data = b"a joined relationship with repeated data".repeat(30);
        let mut selected = options(ArchiveVersion::Rar50).with_hybrid(hybrid);
        selected.features = features;
        let archive = Rar50Writer::new(selected)
            .entry(ArchiveEntry::new(
                b"before".to_vec(),
                EntrySource::from_bytes(data.clone()),
            ))
            .entry(ArchiveEntry::new(
                b"after".to_vec(),
                EntrySource::from_bytes(data.clone()),
            ))
            .finish()
            .unwrap();
        assert_eq!(
            contents(&archive),
            vec![
                (b"before".to_vec(), data.clone()),
                (b"after".to_vec(), data)
            ]
        );
    }
}

#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
#[test]
fn hybrid_worker_schedules_do_not_change_archive_bytes() {
    let encode = |workers| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                let mut writer = Rar50Writer::new(options(ArchiveVersion::Rar50));
                for member in 0..4 {
                    writer = writer.entry(ArchiveEntry::new(
                        format!("member{member}").into_bytes(),
                        EntrySource::from_bytes(vec![member; 512]),
                    ));
                }
                writer.finish().unwrap()
            })
    };
    assert_eq!(encode(1), encode(2));
}
