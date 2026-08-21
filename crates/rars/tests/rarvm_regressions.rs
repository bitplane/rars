use rars::crc32::crc32;
use rars::rar15_40::Archive;
use rars::{ArchiveReadOptions, Result};
use std::cell::RefCell;
use std::io::{Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/rarvm")
        .join(name)
}

struct CollectWriter {
    data: Rc<RefCell<Vec<u8>>>,
}

struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
}

impl Write for CollectWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.data.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn collect_extract(archive: &Archive) -> Result<Vec<CollectedEntry>> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(ArchiveReadOptions::default(), |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter { data }))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
        })
        .collect())
}

#[test]
fn solid_e8_filters_use_member_relative_offsets() {
    let expected_lead = std::fs::read(fixture("solid_e8_filter_lead.txt")).unwrap();
    let expected_exe = std::fs::read(fixture("solid_e8_filter_payload.exe")).unwrap();
    let archive = Archive::parse_path(fixture("solid_e8_filter_member_offset.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"lead.txt");
    assert_eq!(files[0].pack_size, 76);
    assert_eq!(files[0].unp_size, 800);
    assert_eq!(files[1].name, b"tiny_e8e9.exe");
    assert_eq!(files[1].pack_size, 295);
    assert_eq!(files[1].unp_size, 5_884);
    assert!(files[1].is_solid());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_lead);
    assert_eq!(extracted[1].data, expected_exe);
}

#[test]
fn vm_filter_control_stream_accepts_32_bit_encoded_integers() {
    let archive = Archive::parse_path(fixture("vm_encoded_u32_filter.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"bsdcat.exe");

    let mut extracted = Vec::new();
    archive
        .extract_to(ArchiveReadOptions::default(), |meta| {
            extracted.push(meta.name.clone());
            Ok(Box::new(std::io::sink()))
        })
        .unwrap();

    assert_eq!(extracted, vec![b"bsdcat.exe".to_vec()]);
}

#[test]
fn non_standard_vm_filter_uses_generic_executor() {
    let archive = Archive::parse_path(fixture("generic_delta_padding_mutation.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"itanium_synthetic_bundles.bin");
    assert_eq!(files[0].unp_size, 1_048_576);
    assert_eq!(files[0].file_crc, 0x3908_6451);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data.len(), 1_048_576);
    assert_eq!(crc32(&extracted[0].data), 0x3908_6451);
}

#[test]
fn ppmd_embedded_vm_filter_is_applied() {
    // Generated with RAR 3.00 using `-m5 -mc10:16t+ -mce+`: text/PPMd is
    // forced for the member while the x86 executable filter is also forced,
    // so the filter record is carried by PPMd escape 3 instead of LZ symbols.
    let archive = Archive::parse_path(fixture("ppmd_embedded_vm_filter.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"ppmd_branch_mix.bin");
    assert_eq!(files[0].pack_size, 3_351);
    assert_eq!(files[0].unp_size, 710_400);
    assert_eq!(files[0].file_crc, 0xa0fa_ad59);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data.len(), 710_400);
    assert_eq!(crc32(&extracted[0].data), 0xa0fa_ad59);
}

#[test]
fn real_executable_filter_archive_decodes() {
    let archive = Archive::parse_path(fixture("filter_bsdcat_exe.rar")).unwrap();
    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bsdcat.exe");
    assert_eq!(crc32(&extracted[0].data), 0x4db1_0349);
}

#[test]
fn vm_delta_filter_accepts_more_than_thirty_two_channels() {
    let mut expected = Vec::with_capacity(400 * 64);
    for row in 0..400u32 {
        for channel in 0..64u32 {
            expected.push((channel * 7 + row * 3) as u8);
        }
    }
    let archive = Archive::parse_path(fixture("delta_64_channels.rar")).unwrap();

    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"delta64.bin");
    assert_eq!(extracted[0].data, expected);
}
