#[path = "support/scratch.rs"]
mod scratch;
use rars::{ArchiveReader, ArchiveVersion, Builder, ErrorKind, WriterResources};

fn builder(version: ArchiveVersion) -> Builder {
    let mut builder = Builder::new(version).store(true);
    for index in 0..4 {
        builder
            .add_bytes(
                format!("member-{index}").into_bytes(),
                vec![42; 4096],
                None,
                None,
            )
            .unwrap();
    }
    builder
}

#[test]
fn aggregate_limit_preserves_output_and_releases_execution_owners() {
    let root = scratch::case("aggregate-parity");
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for (store, solid, recovery) in [
            (true, false, false),
            (false, false, false),
            (false, true, true),
        ] {
            let builder = builder(version)
                .store(store)
                .solid(solid)
                .recovery_percent(recovery.then_some(10));
            let expected = builder.to_bytes().unwrap();
            let resources = WriterResources::default()
                .with_temp_dir(&*root)
                .with_max_memory_bytes(256 << 20);
            for _ in 0..2 {
                let output = builder.to_output(&resources, None).unwrap();
                assert_eq!(output.as_bytes(), expected);
                assert!(resources.managed_memory_in_use() >= output.as_bytes().len() as u64);
                ArchiveReader::read(output.as_bytes())
                    .unwrap()
                    .test(None)
                    .unwrap();
                let bytes = output.into_vec();
                assert_eq!(resources.managed_memory_in_use(), 0);
                assert_eq!(bytes, expected);
            }
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        }
    }
}

#[test]
fn failed_writes_release_the_group_and_preserve_published_files() {
    let root = scratch::case("aggregate-refusal");
    let path = root.join("archive.rar");
    std::fs::write(&path, b"original").unwrap();
    let resources = WriterResources::default()
        .with_temp_dir(&*root)
        .with_max_memory_bytes(1024);
    for _ in 0..3 {
        let error = builder(ArchiveVersion::Rar50)
            .write_to_path_with_resources(&path, &resources, None)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert_eq!(resources.managed_memory_in_use(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    }
}

#[test]
fn retained_volumes_count_until_copy_and_handoff() {
    let builder = builder(ArchiveVersion::Rar50).volume_size(Some(2048));
    let expected = builder.build_volumes(None).unwrap();
    let resources = WriterResources::default().with_max_memory_bytes(16 << 20);
    let output = builder.to_volume_output(&resources, None).unwrap();
    let retained = resources.managed_memory_in_use();
    let payload: u64 = output
        .volumes()
        .iter()
        .map(|part| part.as_bytes().len() as u64)
        .sum();
    assert!(retained >= payload);
    let copied = output
        .copy_with(|parts| {
            assert_eq!(resources.managed_memory_in_use(), retained + payload);
            parts
                .iter()
                .map(|part| part.as_bytes().to_vec())
                .collect::<Vec<_>>()
        })
        .unwrap();
    assert_eq!(copied, expected);
    assert_eq!(resources.managed_memory_in_use(), retained);
    assert_eq!(output.into_vec().unwrap(), expected);
    assert_eq!(resources.managed_memory_in_use(), 0);
}

#[test]
fn legacy_families_refuse_before_emission_even_with_zero_budget() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let builder = builder(version);
        let resources = WriterResources::default().with_max_memory_bytes(0);
        let mut bytes = Vec::new();
        let error = builder.write_to(&mut bytes, &resources, None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
        assert!(bytes.is_empty());
        assert_eq!(
            builder
                .volume_size(Some(2048))
                .build_volumes_with_resources(&resources, None)
                .unwrap_err()
                .kind(),
            ErrorKind::UnsupportedFeature
        );
        assert_eq!(resources.managed_memory_in_use(), 0);
    }
}
