use rars::rar50::{
    write_streaming_archive_to, Archive, ArchiveEntry, ArchiveExtras, FilterPolicy, Rar50Writer,
    WriterOptions,
};

use rars::rar50::VolumeSink;
use rars::{
    ArchiveVersion, EntrySource, Error, FeatureSet, Result, WriteOperation, WriteProgressEvent,
    WriterResources,
};
use std::{
    cell::RefCell,
    io::{Cursor, Result as IoResult, Write},
    rc::Rc,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[test]
fn volume_compression_plan_refusal_does_not_open_sources_or_start_a_volume() {
    let entries = [rars::rar50::ArchiveEntry::new(
        b"file".to_vec(),
        rars::EntrySource::from_opener(1, || panic!("plan refusal opened source")),
    )];
    let resources = rars::WriterResources::default().with_max_preparation_bytes(0);
    let mut volumes = rars::rar50::CollectedVolumes::new();
    let error = rars::rar50::write_streaming_volumes_to(
        &entries,
        rars::rar50::WriterOptions::new(
            rars::ArchiveVersion::Rar50,
            rars::FeatureSet::store_only(),
        ),
        rars::rar50::ArchiveExtras::default(),
        64,
        &mut volumes,
        &resources,
    )
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
    assert!(volumes.take().is_empty());
}

#[test]
fn collected_volumes_enforce_order_and_report_length_mismatch() {
    let mut volumes = rars::rar50::CollectedVolumes::new();
    assert!(matches!(
        volumes.start_volume(1),
        Err(rars::Error::WriterFailure("volumes arrived out of order"))
    ));
    let mut output = volumes.start_volume(0).unwrap();
    output.write_all(b"abc").unwrap();
    output.flush().unwrap();
    assert!(matches!(
        volumes.finish_volume(0, 2),
        Err(rars::Error::WriterFailure(
            "volume length does not match what was written"
        ))
    ));
    volumes.finish_volume(0, 3).unwrap();
    drop(output);
    assert_eq!(volumes.take(), [b"abc".to_vec()]);
}

#[cfg(feature = "encryption")]
fn write_encrypted(header_encryption: bool, volume_size: Option<usize>) -> Vec<Vec<u8>> {
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50)
        .store(true)
        .password(Some(b"password".to_vec()))
        .header_encryption(header_encryption)
        .volume_size(volume_size);
    for name in ["a", "b", "c", "d", "e", "f"] {
        builder
            .add_bytes(
                name.as_bytes().to_vec(),
                name.repeat(300).into_bytes(),
                None,
                None,
            )
            .unwrap();
    }
    match volume_size {
        Some(_) => builder.build_volumes(None).unwrap(),
        None => vec![builder
            .comment(Some(b"comment".to_vec()))
            .archive_comment_password(Some(b"password".to_vec()))
            .to_bytes()
            .unwrap()],
    }
}

#[cfg(feature = "encryption")]
fn encrypted_writes() -> [(&'static str, bool, Option<usize>); 4] {
    [
        ("plain headers", false, None),
        ("encrypted headers", true, None),
        ("split", false, Some(1024)),
        ("split with encrypted headers", true, Some(1024)),
    ]
}

#[test]
#[cfg(feature = "encryption")]
fn members_share_the_archive_salt_and_draw_fresh_ivs() {
    for (case, header_encryption, volume_size) in encrypted_writes() {
        let parts = write_encrypted(header_encryption, volume_size);
        assert_eq!(parts.len() > 1, volume_size.is_some(), "{case}");
        let volumes = parts
            .iter()
            .map(|part| rars::rar50::Archive::parse_with_password(part, Some(b"password")))
            .collect::<rars::Result<Vec<_>>>()
            .unwrap();
        let mut records = std::collections::BTreeMap::new();
        for volume in &volumes {
            for file in volume.files().chain(volume.services()) {
                if let Some(encryption) = &file.encryption {
                    records.insert(file.name.clone(), (encryption.salt, encryption.iv));
                }
            }
        }
        // Six members, plus the encrypted comment where the write can carry one.
        let blocks = 6 + usize::from(volume_size.is_none());
        assert_eq!(records.len(), blocks, "{case}");
        let salts = records.values().map(|(salt, _)| *salt);
        let ivs = records.values().map(|(_, iv)| *iv);
        assert_eq!(
            salts.collect::<std::collections::BTreeSet<_>>().len(),
            1,
            "{case}"
        );
        assert_eq!(
            ivs.collect::<std::collections::BTreeSet<_>>().len(),
            blocks,
            "{case}"
        );
        if header_encryption {
            // The archive encryption header's salt follows its CRC and its one-byte size,
            // type, flags, version, encryption flags and KDF count fields.
            let (salt, _) = records.values().next().unwrap();
            for part in &parts {
                assert_eq!(&part[18..34], salt, "{case}");
            }
        }

        let mut extracted = 0;
        rars::rar50::extract_volumes_to(
            &volumes,
            rars::ArchiveReadOptions::with_password(b"password"),
            |_| {
                extracted += 1;
                Ok(Box::new(std::io::sink()))
            },
        )
        .unwrap();
        assert_eq!(extracted, 6, "{case}");
        assert!(
            rars::rar50::Archive::parse_with_password(&parts[0], Some(b"wrong")).is_err(),
            "{case}"
        );
    }
}

#[test]
fn empty_volume_set_is_rejected_before_opening_a_sink() {
    let mut sink = rars::rar50::CollectedVolumes::new();
    let error = rars::rar50::write_streaming_volumes_to(
        &[],
        rars::rar50::WriterOptions::default(),
        rars::rar50::ArchiveExtras::default(),
        4096,
        &mut sink,
        &rars::WriterResources::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
    assert!(sink.take().is_empty());
}

struct CollectWriter(Rc<RefCell<Vec<u8>>>);

#[test]
fn stored_writer_does_not_require_lz_workspace() {
    let data = b"stored payload".repeat(1024);
    let write = |limit| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        Rar50Writer::new(
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(0),
        )
        .entries(vec![entry(b"payload", &data)])
        .write_to(&mut out, &WriterResources::new(limit))?;
        Ok(out)
    };
    let bytes = write(1024 * 1024).unwrap();
    assert_eq!(bytes, write(256 * 1024 * 1024).unwrap());
    let archive = rars::ArchiveReader::read_owned(bytes).unwrap();
    assert_eq!(
        archive.read_member(b"payload", None).unwrap().unwrap(),
        data
    );
}

/// Builds a member from bytes the test already holds.
fn entry(name: &[u8], data: &[u8]) -> ArchiveEntry {
    ArchiveEntry::new(
        name.to_vec(),
        EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
    )
}

#[test]
fn compressed_writer_reports_determinate_progress() {
    let data: Vec<u8> = (0usize..128 * 1024)
        .map(|i| (i.wrapping_mul(37) % 251) as u8)
        .collect();
    let entry = entry(b"payload.bin", &data)
        .with_attributes(0x20)
        .with_host_os(1);
    let last = rars::atomic64::AtomicU64::new(0);
    let advances = AtomicUsize::new(0);
    let intermediate = std::sync::atomic::AtomicBool::new(false);
    let reporter = |event: WriteProgressEvent<'_>| {
        if let WriteProgressEvent::Advanced {
            operation: WriteOperation::Compression,
            completed_bytes,
            total_bytes,
            ..
        } = event
        {
            assert!(completed_bytes >= last.swap(completed_bytes, Ordering::Relaxed));
            assert!(completed_bytes <= total_bytes);
            if completed_bytes < total_bytes {
                intermediate.store(true, Ordering::Relaxed);
            }
            advances.fetch_add(1, Ordering::Relaxed);
        }
    };

    Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar70,
        FeatureSet::default(),
    ))
    .entries([entry].to_vec())
    .filter_policy(FilterPolicy::Auto)
    .progress(&reporter)
    .finish()
    .unwrap();

    assert!(advances.load(Ordering::Relaxed) >= 1);
    assert!(intermediate.load(Ordering::Relaxed));
    // Progress is now counted in input bytes, however many passes the
    // filter search makes over them.
    assert_eq!(last.load(Ordering::Relaxed), data.len() as u64);
}

#[test]
#[cfg(feature = "recovery")]
fn recovery_writer_reports_determinate_pass_progress() {
    let entry = entry(b"payload.bin", b"recovery progress payload")
        .with_attributes(0x20)
        .with_host_os(1);
    let starts = AtomicUsize::new(0);
    let advances = AtomicUsize::new(0);
    let finishes = AtomicUsize::new(0);
    let reporter = |event: WriteProgressEvent<'_>| match event {
        WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Recovery,
            total_bytes: Some(total),
            ..
        } => {
            assert!(total > 0);
            starts.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::Advanced {
            operation: WriteOperation::Recovery,
            completed_bytes,
            total_bytes,
            ..
        } => {
            assert!(completed_bytes <= total_bytes);
            advances.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            ..
        } => {
            finishes.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    };
    let features = FeatureSet::store_only();

    Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(0))
        .entries([entry].to_vec())
        .recovery_percent(Some(10))
        .progress(&reporter)
        .finish()
        .unwrap();

    assert!(starts.load(Ordering::Relaxed) >= 1);
    assert!(advances.load(Ordering::Relaxed) >= 1);
    assert_eq!(
        starts.load(Ordering::Relaxed),
        finishes.load(Ordering::Relaxed)
    );
}

impl Write for CollectWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Historical numeric snapshots; timestamp presence has dedicated regression tests.
struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    is_directory: bool,
}

fn collect_extract(archive: &Archive) -> Result<Vec<CollectedEntry>> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(rars::ArchiveReadOptions::default(), |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter(data)))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time.unwrap_or(0),
            attr: meta.attr,
            host_os: meta.host_os,
            is_directory: meta.is_directory,
        })
        .collect())
}

#[test]
fn streaming_writer_round_trips_across_input_blocks() {
    let data = b"bounded streaming member data\n".repeat(80_000);
    let entry = ArchiveEntry::new(
        b"large.txt".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
    )
    .with_mtime(None)
    .with_attributes(0x20)
    .with_host_os(1);
    let mut bytes = Vec::new();
    write_streaming_archive_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        ArchiveExtras::default(),
        &WriterResources::default(),
        &mut bytes,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"large.txt");
    assert_eq!(extracted[0].data, data);
}

#[test]
fn streaming_writer_rejects_workspace_larger_than_budget() {
    let entry = ArchiveEntry::new(
        b"small.txt".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(&b"small"[..])),
    )
    .with_mtime(None)
    .with_attributes(0x20)
    .with_host_os(1);
    let result = write_streaming_archive_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        ArchiveExtras::default(),
        &WriterResources::new(1024),
        &mut Vec::new(),
    );
    assert!(matches!(result, Err(Error::MemoryLimitExceeded { .. })));
}

#[test]
fn unfiltered_optimal_streaming_fits_a_ceiling_sized_for_its_members() {
    // Charging every job a full 1 MiB optimal block asked for 173 MB here.
    let mut state = 0x1234_5678u32;
    let data: Vec<u8> = (0..160 * 1024)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    let entries = ["first", "second"]
        .map(|name| ArchiveEntry::new(name, EntrySource::from_bytes(Arc::<[u8]>::from(&data[..]))));
    let limit = 96 * 1024 * 1024;
    let mut bytes = Vec::new();
    write_streaming_archive_to(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(3)
            .with_dictionary_size(128 * 1024),
        ArchiveExtras::default().with_filter_policy(FilterPolicy::None),
        &WriterResources::new(limit).with_max_memory_bytes(limit),
        &mut bytes,
    )
    .unwrap();
    let archive = rars::ArchiveReader::read_owned(bytes).unwrap();
    assert_eq!(archive.read_member(b"second", None).unwrap().unwrap(), data);
}

#[test]
fn streaming_writer_rejects_a_source_larger_than_its_declared_size() {
    let source = EntrySource::from_opener(4, || Ok(Box::new(Cursor::new(b"data!".to_vec()))));
    let entry = ArchiveEntry::new(b"changing.bin".to_vec(), source)
        .with_attributes(0x20)
        .with_host_os(1);
    let result = write_streaming_archive_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        ArchiveExtras::default(),
        &WriterResources::default(),
        &mut Vec::new(),
    );
    let error = result.unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
    assert_eq!(
        error.entry_context(),
        Some((b"changing.bin".as_slice(), "compressing"))
    );
}

#[test]
#[cfg(feature = "encryption")]
fn encrypted_streaming_writer_round_trips_across_input_blocks() {
    let data = b"encrypted bounded streaming member data\n".repeat(40_000);
    let entry = ArchiveEntry::new(
        b"secret.txt".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
    )
    .with_mtime(None)
    .with_attributes(0x20)
    .with_host_os(1)
    .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let mut bytes = Vec::new();
    write_streaming_archive_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar50, features),
        ArchiveExtras::default(),
        &WriterResources::default(),
        &mut bytes,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let entries = RefCell::new(Vec::new());
    archive
        .extract_to(
            rars::ArchiveReadOptions::with_password(b"password"),
            |meta| {
                let output = Rc::new(RefCell::new(Vec::new()));
                entries
                    .borrow_mut()
                    .push((meta.name.clone(), Rc::clone(&output)));
                Ok(Box::new(CollectWriter(output)))
            },
        )
        .unwrap();
    let entries = entries.into_inner();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, b"secret.txt");
    assert_eq!(*entries[0].1.borrow(), data);
}

#[test]
fn writer_stamps_requested_rar50_dictionary_size() {
    let data = b"RAR5 dictionary-size writer option fixture".repeat(64);
    let options = WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::default())
        .with_dictionary_size(512 * 1024);
    let entries = [entry(b"dict.bin", &data)
        .with_attributes(0x20)
        .with_host_os(3)];
    let archive = Rar50Writer::new(options)
        .entries(entries.to_vec())
        .finish()
        .unwrap();

    let parsed = Archive::parse(&archive).unwrap();
    let info = parsed
        .files()
        .next()
        .unwrap()
        .decoded_compression_info()
        .unwrap();
    let extracted = collect_extract(&parsed).unwrap();

    assert_eq!(info.algorithm_version, 0);
    assert_eq!(info.dictionary_size, 512 * 1024);
    assert_eq!(extracted[0].data, data);
}

#[test]
fn writer_uses_rar7_dictionary_fields_when_size_needs_v1_encoding() {
    let data = b"RAR7 dictionary-size writer option fixture".repeat(64);
    let options = WriterOptions::new(rars::ArchiveVersion::Rar70, rars::FeatureSet::default())
        .with_dictionary_size(192 * 1024);
    let entries = [entry(b"dict7.bin", &data)
        .with_attributes(0x20)
        .with_host_os(3)];
    let archive = Rar50Writer::new(options)
        .entries(entries.to_vec())
        .finish()
        .unwrap();

    let parsed = Archive::parse(&archive).unwrap();
    let info = parsed
        .files()
        .next()
        .unwrap()
        .decoded_compression_info()
        .unwrap();
    let extracted = collect_extract(&parsed).unwrap();

    assert_eq!(info.algorithm_version, 1);
    assert_eq!(info.dictionary_size, 192 * 1024);
    assert_eq!(extracted[0].data, data);
}

#[test]
fn writer_rejects_unencodable_rar50_dictionary_size() {
    let options = WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::default())
        .with_dictionary_size(192 * 1024);
    let entries = [entry(b"bad.bin", b"data data data data")
        .with_attributes(0x20)
        .with_host_os(3)];

    assert!(matches!(
        Rar50Writer::new(options).entries(entries.to_vec()).finish(),
        Err(Error::InvalidArgument(
            "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB"
        ))
    ));
}

#[test]
fn writer_options_default_targets_rar50_with_store_only_features() {
    let options = WriterOptions::default();
    assert_eq!(options.target, rars::ArchiveVersion::Rar50);
    assert_eq!(options.features, rars::FeatureSet::store_only());
}
