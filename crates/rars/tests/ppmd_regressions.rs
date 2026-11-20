use rars::crc32::crc32;
use rars::rar15_40::Archive;
use rars::{ArchiveMember, ArchiveReadOptions, ArchiveReader, ExtractionErrorAction, Result};
use std::cell::RefCell;
use std::io::{Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40/ppmd")
        .join(name)
}

struct CollectWriter {
    data: Rc<RefCell<Vec<u8>>>,
}

struct CollectedEntry {
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
        .map(|(_meta, data)| CollectedEntry {
            data: data.borrow().clone(),
        })
        .collect())
}

#[test]
fn ppmd_block_can_emit_embedded_lz_distance_matches() {
    let expected = std::fs::read(fixture("ppmd_lz_match.txt")).unwrap();
    let archive = Archive::parse_path(fixture("ppmd_lz_match_rar300.rar")).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"repeated_phrase_64k.txt");
    assert_eq!(files[0].method, 0x35);
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[0].pack_size, 193);
    assert_eq!(files[0].unp_size, 44_544);
    assert_eq!(files[0].file_crc, 0x884fab33);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x884fab33);
}

#[test]
fn ppmd_block_can_emit_embedded_one_byte_lz_repeats() {
    let archive = Archive::parse_path(fixture("ppmd_lz_repeat_rar3.cbr")).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"testfile.jpg");
    assert_eq!(files[0].method, 0x35);
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[0].pack_size, 182);
    assert_eq!(files[0].unp_size, 220);
    assert_eq!(files[0].file_crc, 0xda70b16c);
    assert_eq!(files[1].name, b"testfile.png");
    assert_eq!(files[1].method, 0x35);
    assert_eq!(files[1].unp_ver, 29);
    assert_eq!(files[1].pack_size, 84);
    assert_eq!(files[1].unp_size, 87);
    assert_eq!(files[1].file_crc, 0xafb0ac62);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(crc32(&extracted[0].data), 0xda70b16c);
    assert_eq!(crc32(&extracted[1].data), 0xafb0ac62);
}

/// Fuzzed solid archives whose first member fails partway through a PPMd
/// symbol. Reading on past it with a member error handler, the later member
/// continues the model, which the failed symbol left half-updated. It must
/// fail as a missing model; it used to panic indexing the model's memory.
#[test]
fn a_member_continuing_a_failed_ppmd_model_fails_cleanly() {
    for (name, first) in [
        (
            "salvage_cut_mid_symbol.rar",
            "RAR 2.9 bitstream is truncated",
        ),
        (
            "salvage_escape_past_root.rar",
            "RAR 2.9 PPMd model is corrupt",
        ),
    ] {
        let data = std::fs::read(fixture(name)).unwrap();
        let failures = Mutex::new(Vec::new());
        let handler = |member: &ArchiveMember, error: &rars::Error| {
            failures
                .lock()
                .unwrap()
                .push((member.meta.name_lossy(), error.to_string()));
            Ok(ExtractionErrorAction::Continue)
        };
        let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
        let archive = ArchiveReader::read_with_options(&data, options).unwrap();
        let names: Vec<_> = archive.members().map(|m| m.meta.name_lossy()).collect();
        assert_eq!(names.len(), 2, "{name}");

        archive.test_with_options(options).unwrap();
        let expected: Vec<_> = [first, "RAR PPMd block reuses missing model"]
            .into_iter()
            .zip(&names)
            .map(|(error, name)| {
                let error = format!("while extracting entry '{name}': {error}");
                (name.clone(), error)
            })
            .collect();
        assert_eq!(*failures.lock().unwrap(), expected, "{name}");

        failures.lock().unwrap().clear();
        archive
            .extract_to_with_options(options, |_| Ok(Box::new(std::io::sink())))
            .unwrap();
        assert_eq!(*failures.lock().unwrap(), expected, "{name}");
    }
}
