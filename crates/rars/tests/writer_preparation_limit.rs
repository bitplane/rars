#[path = "support/scratch.rs"]
mod scratch;
use rars::{ArchiveReader, ArchiveVersion, Builder, Error, ErrorKind, WriterResources};

#[test]
fn preparation_limit_preserves_plain_output_and_releases_failed_writes() {
    let root = scratch::case("preparation-byte-parity");
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for (store, solid, recovery) in [
            (true, false, false),
            (false, false, false),
            (false, true, true),
        ] {
            let mut builder = Builder::new(target)
                .store(store)
                .solid(solid)
                .comment(Some(vec![b'c'; 4096]))
                .archive_metadata(None, false, true)
                .unwrap()
                .recovery_percent(recovery.then_some(10));
            for index in 0..8 {
                builder
                    .add_bytes(
                        format!("member-{index}").into_bytes(),
                        vec![42; 1024],
                        None,
                        None,
                    )
                    .unwrap();
            }
            let base = WriterResources::default().with_temp_dir(&*root);
            let mut expected = Vec::new();
            builder.write_to(&mut expected, &base, None).unwrap();
            let denied = base.clone().with_max_preparation_bytes(0);
            let mut output = Vec::new();
            assert!(matches!(
                builder
                    .write_to(&mut output, &denied, None)
                    .unwrap_err()
                    .root_cause(),
                Error::WriterPreparationLimitExceeded { limit: 0, .. }
            ));
            assert!(output.is_empty());
            let resources = base.with_max_preparation_bytes(1 << 20);
            assert_eq!(resources.max_preparation_bytes(), Some(1 << 20));
            let mut unavailable: &mut [u8] = &mut [];
            assert_eq!(
                builder
                    .write_to(&mut unavailable, &resources, None)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Io
            );
            for _ in 0..2 {
                output.clear();
                builder.write_to(&mut output, &resources, None).unwrap();
                assert_eq!(output, expected);
                ArchiveReader::read(&output).unwrap().test(None).unwrap();
            }
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        }
    }
}

#[test]
fn legacy_writers_refuse_the_unsupported_hard_policy_before_emission() {
    for target in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(target).store(true);
        builder
            .add_bytes(b"member".to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        let mut output = Vec::new();
        let error = builder
            .write_to(
                &mut output,
                &WriterResources::default().with_max_preparation_bytes(u64::MAX),
                None,
            )
            .unwrap_err();
        assert!(matches!(
            error.root_cause(),
            Error::UnsupportedFamilyFeature {
                feature: "preparation memory quota",
                ..
            }
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn volume_headers_and_encryption_state_obey_preparation_policy() {
    use rars::rar50::{
        write_streaming_volumes_to, ArchiveEntry, ArchiveExtras, CollectedVolumes, WriterOptions,
    };
    let root = scratch::case("preparation-volumes");
    for encrypted in [false, true] {
        let mut entry = ArchiveEntry::new(
            b"member".to_vec(),
            rars::EntrySource::from_bytes(vec![42; 8192]),
        );
        if encrypted {
            entry.password = Some(b"secret".to_vec());
        }
        let entries = [entry];
        let mut options = WriterOptions::default();
        options.compression_level = Some(0);
        options.features.header_encryption = encrypted;
        let mut extras = ArchiveExtras::default();
        extras.recovery_percent = Some(10);
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_preparation_bytes(1 << 20);
        let mut sink = CollectedVolumes::new();
        write_streaming_volumes_to(&entries, options, extras, 2048, &mut sink, &resources).unwrap();
        let archives: Vec<_> = sink
            .take()
            .into_iter()
            .map(|bytes| {
                ArchiveReader::read_owned_with_options(
                    bytes,
                    rars::ArchiveReadOptions::with_optional_password(
                        encrypted.then_some(b"secret".as_slice()),
                    ),
                )
                .unwrap()
            })
            .collect();
        assert!(archives.len() > 1);
        assert_eq!(
            rars::read_volume_member_at(&archives, 0, encrypted.then_some(b"secret".as_slice()))
                .unwrap()
                .unwrap(),
            vec![42; 8192]
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_after_preparation_releases_capacity_for_reuse() {
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
    let root = scratch::case("preparation-cancel");
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_preparation_bytes(16384);
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .archive_metadata(None, false, true)
        .unwrap();
    builder
        .add_bytes(b"member".to_vec(), vec![42; 1024], None, None)
        .unwrap();
    for _ in 0..32 {
        let progress = CancelAtEmission(AtomicBool::new(false));
        assert_eq!(
            builder
                .write_to(&mut Vec::new(), &resources, Some(&progress))
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
        builder.write_to(&mut Vec::new(), &resources, None).unwrap();
    }
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}
