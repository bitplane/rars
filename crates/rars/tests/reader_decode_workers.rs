#![cfg(feature = "write")]
#![cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]

use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder};
use std::{cell::RefCell, io, io::Write, rc::Rc};

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn member(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut data = Vec::with_capacity(len + 64);
    while data.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        if state >> 29 == 0 && data.len() > 64 {
            let from = data.len() - 1 - (state >> 8) as usize % 64;
            data.extend_from_within(from..from + 1);
        }
        data.push((state >> 16) as u8);
    }
    data.truncate(len);
    data
}

fn solid_archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(false).solid(true);
    for (index, data) in members.iter().enumerate() {
        builder
            .add_bytes(
                format!("member{index}").into_bytes(),
                data.clone(),
                None,
                None,
            )
            .unwrap();
    }
    builder.to_bytes().unwrap()
}

fn extract(archive: &[u8], workers: usize) -> (Vec<u8>, Option<String>) {
    let output = Rc::new(RefCell::new(Vec::new()));
    let options = ArchiveReadOptions::new()
        .with_rar50_buffered_decode_limit(0)
        .with_rar50_decode_workers(workers);
    let result = ArchiveReader::read_owned(archive.to_vec())
        .and_then(|archive| {
            archive.extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
        })
        .err()
        .map(|error| error.to_string());
    let bytes = output.borrow().clone();
    (bytes, result)
}

#[test]
fn decode_workers_extract_the_same_bytes_as_serial_decoding() {
    let members = [member(1_500_000, 3), member(1_200_000, 5)];
    let archive = solid_archive(&members);
    for workers in [0, 1, 4] {
        let (bytes, error) = extract(&archive, workers);
        assert_eq!(error, None, "workers={workers}");
        assert!(bytes == members.concat(), "workers={workers}");
    }
}

#[test]
fn decode_workers_fail_on_a_damaged_member_where_serial_decoding_does() {
    let mut archive = solid_archive(&[member(1_500_000, 7), member(1_200_000, 9)]);
    let at = archive.len() * 3 / 5;
    archive[at] ^= 0x40;
    let serial = extract(&archive, 0);
    assert!(serial.1.is_some());
    for workers in [1, 4] {
        let ahead = extract(&archive, workers);
        assert_eq!(ahead.1, serial.1, "workers={workers}");
        assert!(ahead.0 == serial.0, "workers={workers}");
    }
}
