use rars::{crc32::crc32, ArchiveReader};
use std::cell::RefCell;
use std::io::{self, Write};
use std::path::Path;
use std::rc::Rc;

struct Collect(Rc<RefCell<Vec<u8>>>);

impl Write for Collect {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/rars/tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn decode(name: &str) -> Vec<Vec<u8>> {
    let archive = ArchiveReader::read(&fixture(name)).unwrap();
    let mut outputs = Vec::new();
    archive
        .extract_to(None, |_| {
            let output = Rc::new(RefCell::new(Vec::new()));
            outputs.push(output.clone());
            Ok(Box::new(Collect(output)))
        })
        .unwrap();
    outputs
        .into_iter()
        .map(|output| Rc::try_unwrap(output).unwrap().into_inner())
        .collect()
}

#[test]
fn historical_rar13_and_rar15_decode_original_contents() {
    assert_eq!(decode("rar13/README.RAR"), [fixture("rar13/README")]);
    assert_eq!(
        decode("rar15_40/rar154/readme_154_normal.rar"),
        [fixture("rar15_40/rar154/expected/README.md")]
    );
}

#[test]
fn rar20_large_lz_decodes_with_expected_checksum() {
    let outputs = decode("rar15_40/rar250/BIGLZ.RAR");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].len(), 167_936);
    assert_eq!(crc32(&outputs[0]), 0x46ce9077);
}

#[test]
fn rar29_solid_history_preserves_both_members() {
    assert_eq!(
        decode("rar15_40/rar300/solid_simple_rar300.rar"),
        [
            b"shared prefix shared prefix shared prefix alpha\n".to_vec(),
            b"shared prefix shared prefix shared prefix beta\n".to_vec(),
        ]
    );
}

#[test]
fn ppmd_and_modern_filtered_archives_pass_integrity_checks() {
    for name in [
        "rar15_40/ppmd/ppmd_lorem_rar300.rar",
        "rar50/m5_max.rar",
        "rar50/filter_e8e9.rar",
        "rar50/filter_delta.rar",
        "rar50/filter_arm.rar",
        "golden/stored_rar70.rar",
    ] {
        let outputs = decode(name);
        assert!(!outputs.is_empty(), "{name}");
        assert!(outputs.iter().any(|output| !output.is_empty()), "{name}");
    }
}

#[test]
fn legacy_and_modern_split_members_keep_volume_history() {
    let sets = [
        vec![
            "rar13/MULTIVOL.RAR".to_owned(),
            "rar13/MULTIVOL.R00".to_owned(),
            "rar13/MULTIVOL.R01".to_owned(),
            "rar13/MULTIVOL.R02".to_owned(),
        ],
        (1..=6)
            .map(|part| format!("rar50/solid_multivol.part{part:02}.rar"))
            .collect(),
    ];
    for (index, names) in sets.into_iter().enumerate() {
        let volumes: Vec<_> = names
            .iter()
            .map(|name| ArchiveReader::read(&fixture(name)).unwrap())
            .collect();
        let mut outputs = Vec::new();
        rars::extract_volumes_to(&volumes, None, |_| {
            let output = Rc::new(RefCell::new(Vec::new()));
            outputs.push(output.clone());
            Ok(Box::new(Collect(output)))
        })
        .unwrap();
        if index == 0 {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].borrow().len(), 65_536);
            assert_eq!(rars::rar13::file_checksum(&outputs[0].borrow()), 0x4649);
        } else {
            assert_eq!(outputs.len(), 2);
            assert_eq!(&*outputs[0].borrow(), b"AAAAAAAA\n");
            assert_eq!(outputs[1].borrow().len(), 65_536);
            assert_eq!(crc32(&outputs[1].borrow()), 0xddc9_5682);
        }
    }
}

#[test]
fn reader_controls_refuse_output_before_opening_a_sink() {
    let archive = ArchiveReader::read(&fixture("rar13/README.RAR")).unwrap();
    let options = rars::ArchiveReadOptions::default().with_max_member_output_bytes(0);
    let mut opened = 0;
    assert!(archive
        .extract_to_with_options(options, |_| {
            opened += 1;
            Ok(Box::new(io::sink()))
        })
        .is_err());
    assert_eq!(opened, 0);

    let cancellation = rars::ReadCancellation::new();
    cancellation.cancel();
    let options = rars::ArchiveReadOptions::default().with_cancellation(&cancellation);
    assert!(ArchiveReader::read_with_options(&fixture("rar13/README.RAR"), options).is_err());
}

#[test]
fn recovery_record_metadata_remains_readable() {
    let archive = ArchiveReader::read(&fixture("rar50/with_recovery.rar")).unwrap();
    let rars::Archive::Rar50Plus(archive) = archive else {
        panic!("RAR5 fixture family");
    };
    assert!(archive
        .services()
        .any(|service| service.recovery_record().unwrap().is_some()));
}

#[test]
fn recovery_checksums_do_not_require_repair_algorithms() {
    assert_eq!(rars::recovery::rar5::crc64_xz(b""), 0);
    assert_eq!(
        rars::recovery::rar5::crc64_xz(b"123456789"),
        0x995d_c9bb_df19_39fa
    );
    assert_eq!(
        rars::recovery::rar5::crc64_rar_state(b"te\x80st"),
        0xb5db_f958_3a6e_ed4a
    );
}

#[cfg(not(any(feature = "full", feature = "recovery")))]
#[test]
fn unavailable_recovery_returns_a_typed_error_without_output() {
    let archive = ArchiveReader::read(&fixture("rar50/with_recovery.rar")).unwrap();
    let mut output = Vec::new();
    let error = archive.repair_recovery_to(&mut output).unwrap_err();
    assert_eq!(
        error.root_cause(),
        &rars::Error::FeatureDisabled {
            feature: "recovery"
        }
    );
    assert_eq!(error.kind(), rars::ErrorKind::UnsupportedFeature);
    assert_eq!(error.to_string(), "Cargo feature recovery is disabled");
    assert!(output.is_empty());

    let archive = ArchiveReader::read(&fixture("rar15_40/rar250_protect_head_rr1.rar")).unwrap();
    assert_eq!(
        archive.repair_recovery().unwrap_err().root_cause(),
        &rars::Error::FeatureDisabled {
            feature: "recovery"
        }
    );
    let mut called = false;
    let error = rars::rar15_40::repair_rev3_volumes_to(&[], 1, &[], |_, _| {
        called = true;
        Ok(())
    })
    .unwrap_err();
    assert!(!called);
    assert_eq!(error.kind(), rars::ErrorKind::UnsupportedFeature);
}

#[cfg(not(any(feature = "full", feature = "recovery")))]
#[test]
fn unavailable_recovery_generation_refuses_before_reading_sources() {
    let source =
        rars::EntrySource::from_opener(1, || panic!("recovery refusal must precede source I/O"));
    let entry = rars::rar50::ArchiveEntry::new(b"file".to_vec(), source);
    let writer = rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::default())
        .entry(entry)
        .recovery_percent(Some(1));
    let mut output = Vec::new();
    let error = writer
        .write_to(&mut output, &rars::WriterResources::default())
        .unwrap_err();
    assert_eq!(
        error.root_cause(),
        &rars::Error::FeatureDisabled {
            feature: "recovery"
        }
    );
    assert!(output.is_empty());
}

#[cfg(any(feature = "full", feature = "recovery"))]
#[test]
fn enabled_recovery_preserves_healthy_legacy_and_modern_archives() {
    for name in [
        "rar15_40/rar250_protect_head_rr1.rar",
        "golden/stored_recovery_1.rar",
    ] {
        let input = fixture(name);
        let archive = ArchiveReader::read(&input).unwrap();
        let repaired = archive.repair_recovery_with_report(None).unwrap();
        assert!(!repaired.report.changed, "{name}");
        assert_eq!(repaired.data, input, "{name}");
    }
}
