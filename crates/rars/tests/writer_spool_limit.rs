#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveReader, ArchiveVersion, Builder, Error, ErrorKind, WriterResources};
use std::io::Write;

#[test]
fn spool_quota_does_not_change_successful_archive_bytes() {
    let root = scratch::case("writer-spool-byte-parity");
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for (stored, solid, recovery) in [
            (true, false, false),
            (false, false, false),
            (false, true, false),
            (true, false, true),
            (false, false, true),
        ] {
            let mut builder = Builder::new(target)
                .store(stored)
                .solid(solid)
                .recovery_percent(recovery.then_some(10));
            builder
                .add_bytes(b"first".to_vec(), b"test data ".repeat(512), None, None)
                .unwrap();
            builder
                .add_bytes(b"second".to_vec(), vec![42; 2048], None, None)
                .unwrap();
            let unlimited = WriterResources::default().with_temp_dir(&*root);
            let limited = unlimited.clone().with_max_spool_bytes(1 << 20);
            let mut expected = Vec::new();
            let mut actual = Vec::new();
            builder.write_to(&mut expected, &unlimited, None).unwrap();
            builder.write_to(&mut actual, &limited, None).unwrap();
            assert_eq!(
                actual, expected,
                "{target:?}, stored={stored}, solid={solid}, recovery={recovery}"
            );
            ArchiveReader::read_owned(actual)
                .unwrap()
                .test(None)
                .unwrap();
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        }
    }
}

#[test]
fn spool_refusal_is_typed_and_resources_can_be_reused_after_failure() {
    let root = scratch::case("writer-spool-refusal");
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_bytes(0);
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"member".to_vec(), vec![42; 16384], None, None)
        .unwrap();
    let error = builder
        .write_to(&mut Vec::new(), &resources, None)
        .unwrap_err();
    assert!(
        matches!(
            error.root_cause(),
            Error::WriterSpoolLimitExceeded { limit: 0, .. }
        ),
        "{error:?}"
    );
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    // Plain stored output needs no nonempty spool. The quota is not an output cap.
    let stored = builder.store(true);
    let mut bytes = Vec::new();
    stored.write_to(&mut bytes, &resources, None).unwrap();
    assert!(bytes.len() > 16384);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn recovery_payload_growth_preserves_spool_error_details() {
    let root = scratch::case("writer-spool-recovery");
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(10));
    builder
        .add_bytes(b"member".to_vec(), vec![42; 1024], None, None)
        .unwrap();
    // Enough for the prefix; insufficient for prefix plus the recovery payload.
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_bytes(1200);
    let error = builder
        .write_to(&mut Vec::new(), &resources, None)
        .unwrap_err();
    assert!(
        matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { limit: 1200, used, .. } if *used >= 1024),
        "{error:?}"
    );
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn encrypted_volume_preparation_uses_the_shared_spool_quota() {
    use rars::rar50::{
        write_streaming_volumes_to, ArchiveEntry, ArchiveExtras, CollectedVolumes, WriterOptions,
    };
    let root = scratch::case("writer-spool-volumes");
    let mut entry = ArchiveEntry::new(
        b"member".to_vec(),
        rars::EntrySource::from_bytes(vec![42; 8192]),
    );
    entry.password = Some(b"secret".to_vec());
    let entries = [entry];
    let limited = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_bytes(0);
    let mut options = WriterOptions::default();
    options.compression_level = Some(0);
    let error = write_streaming_volumes_to(
        &entries,
        options,
        ArchiveExtras::default(),
        4096,
        &mut CollectedVolumes::new(),
        &limited,
    )
    .unwrap_err();
    assert!(
        matches!(
            error.root_cause(),
            Error::WriterSpoolLimitExceeded { limit: 0, .. }
        ),
        "{error:?}"
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    let sufficient = limited.with_max_spool_bytes(1 << 20);
    let mut sink = CollectedVolumes::new();
    write_streaming_volumes_to(
        &entries,
        options,
        ArchiveExtras::default(),
        4096,
        &mut sink,
        &sufficient,
    )
    .unwrap();
    let archives: Vec<_> = sink
        .take()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect();
    assert!(archives.len() > 1);
    let data = rars::read_volume_member_at(&archives, 0, Some(b"secret"))
        .unwrap()
        .unwrap();
    assert_eq!(data, vec![42; 8192]);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn recovery_io_bridge_preserves_resource_error_context() {
    let expected = Error::WriterSpoolLimitExceeded {
        limit: 10,
        required: 12,
        used: 8,
    }
    .at_entry(b"\xff".to_vec(), "writing");
    let recovery = rars::recovery::rar5::Error::from(std::io::Error::other(expected.clone()));
    assert_eq!(Error::from(recovery), expected);
}

#[test]
fn sink_failure_still_cleans_up_spools_under_a_quota() {
    struct Refuse;
    impl Write for Refuse {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let root = scratch::case("writer-spool-sink-failure");
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_bytes(1 << 20);
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"member".to_vec(), vec![42; 16384], None, None)
        .unwrap();
    assert_eq!(
        builder
            .write_to(&mut Refuse, &resources, None)
            .unwrap_err()
            .kind(),
        ErrorKind::Io
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    builder.write_to(&mut Vec::new(), &resources, None).unwrap();
}

#[test]
fn cancellation_after_preparation_releases_retained_spools() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct CancelAtEmission(AtomicBool);
    impl rars::WriteProgress for CancelAtEmission {
        fn report(&self, event: rars::WriteProgressEvent<'_>) {
            if matches!(
                event,
                rars::WriteProgressEvent::OperationStarted {
                    operation: rars::WriteOperation::Emission,
                    ..
                }
            ) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }
    let root = scratch::case("writer-spool-cancel");
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_bytes(1 << 20);
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"member".to_vec(), vec![42; 16384], None, None)
        .unwrap();
    let progress = CancelAtEmission(AtomicBool::new(false));
    assert_eq!(
        builder
            .write_to(&mut Vec::new(), &resources, Some(&progress))
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    builder.write_to(&mut Vec::new(), &resources, None).unwrap();
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[test]
fn native_file_spools_do_not_consume_the_memory_payload_quota() {
    let root = scratch::case("writer-spool-native-memory");
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_spool_memory_bytes(0)
        .with_max_spool_bytes(1 << 20);
    assert_eq!(resources.max_spool_memory_bytes(), Some(0));
    assert_eq!(resources.max_spool_bytes(), Some(1 << 20));
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"member".to_vec(), vec![42; 16384], None, None)
        .unwrap();
    let mut output = Vec::new();
    builder.write_to(&mut output, &resources, None).unwrap();
    assert_eq!(
        ArchiveReader::read_owned(output)
            .unwrap()
            .read_member(b"member", None)
            .unwrap()
            .unwrap(),
        vec![42; 16384]
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}
