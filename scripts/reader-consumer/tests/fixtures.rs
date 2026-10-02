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
