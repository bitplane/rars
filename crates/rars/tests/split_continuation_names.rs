#![cfg(feature = "write")]

use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, ExtractedEntryMeta};
use std::io::Write;
use std::sync::{Arc, Mutex};

type Outputs = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

const VERSIONS: [ArchiveVersion; 4] = [
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2654435761) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn build_set(version: ArchiveVersion, stored: bool, name: &[u8], data: &[u8]) -> Vec<Vec<u8>> {
    let mut builder = Builder::new(version).store(stored).volume_size(Some(4096));
    builder
        .add_bytes(name.to_vec(), data.to_vec(), None, None)
        .unwrap();
    let volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() > 2, "{version:?}: need a middle volume");
    volumes
}

fn rename_continuation(volume: &mut Vec<u8>, name: &[u8]) {
    match ArchiveReader::read(volume).unwrap() {
        Archive::Rar15To40(archive) => {
            let file = archive.files().next().unwrap();
            assert!(file.is_split_before());
            rename_rar15_header(volume, file, name);
        }
        Archive::Rar50Plus(archive) => {
            let file = archive.files().next().unwrap();
            assert!(file.is_split_before());
            rename_rar5_header(volume, file.block.offset, name);
        }
        _ => unreachable!("only RAR 1.5 and later are under test"),
    }
}

const FHD_LARGE: u16 = 0x0100;
const HEAD_SIZE_AT: usize = 5;
const NAME_SIZE_AT: usize = 26;

fn rename_rar15_header(volume: &mut Vec<u8>, file: &rars::rar15_40::FileHeader, name: &[u8]) {
    let start = file.block.offset;
    let fixed_len = if file.block.flags & FHD_LARGE != 0 {
        40
    } else {
        32
    };
    let name_at = start + fixed_len;
    volume.splice(name_at..name_at + file.name.len(), name.iter().copied());
    let head_size = file.block.head_size as usize - file.name.len() + name.len();
    let head_size_at = start + HEAD_SIZE_AT;
    volume[head_size_at..head_size_at + 2].copy_from_slice(&(head_size as u16).to_le_bytes());
    let name_size_at = start + NAME_SIZE_AT;
    volume[name_size_at..name_size_at + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
    let crc = rars::crc32::crc32(&volume[start + 2..start + head_size]) as u16;
    volume[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn read_vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    value
}

fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

const HFL_EXTRA: u64 = 0x01;
const HFL_DATA: u64 = 0x02;
const FHFL_UTIME: u64 = 0x02;
const FHFL_CRC32: u64 = 0x04;

fn rename_rar5_header(volume: &mut Vec<u8>, start: usize, name: &[u8]) {
    let mut at = start + 4;
    let head_size = read_vint(volume, &mut at) as usize;
    let body_start = at;
    let body_end = body_start + head_size;
    read_vint(volume, &mut at);
    let flags = read_vint(volume, &mut at);
    if flags & HFL_EXTRA != 0 {
        read_vint(volume, &mut at);
    }
    if flags & HFL_DATA != 0 {
        read_vint(volume, &mut at);
    }
    let file_flags = read_vint(volume, &mut at);
    read_vint(volume, &mut at);
    read_vint(volume, &mut at);
    if file_flags & FHFL_UTIME != 0 {
        at += 4;
    }
    if file_flags & FHFL_CRC32 != 0 {
        at += 4;
    }
    read_vint(volume, &mut at);
    read_vint(volume, &mut at);
    let name_len_at = at;
    let old_len = read_vint(volume, &mut at) as usize;
    let mut body = volume[body_start..name_len_at].to_vec();
    body.extend(vint(name.len() as u64));
    body.extend_from_slice(name);
    body.extend_from_slice(&volume[at + old_len..body_end]);
    let mut header = vint(body.len() as u64);
    header.extend(body);
    let crc = rars::crc32::crc32(&header);
    let mut sealed = crc.to_le_bytes().to_vec();
    sealed.extend(header);
    volume.splice(start..body_end, sealed);
}

fn extract(volumes: &[Vec<u8>]) -> rars::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let archives: Vec<Archive> = volumes
        .iter()
        .map(|bytes| ArchiveReader::read_owned(bytes.clone()))
        .collect::<rars::Result<_>>()?;
    let outputs: Outputs = Arc::default();
    let sink = outputs.clone();
    rars::extract_volumes_to(&archives, None, move |meta: &ExtractedEntryMeta| {
        sink.lock().unwrap().push((meta.name.clone(), Vec::new()));
        Ok(Box::new(Collect(sink.clone())) as Box<dyn Write>)
    })?;
    let outputs = outputs.lock().unwrap().clone();
    Ok(outputs)
}

struct Collect(Outputs);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut outputs = self.0.lock().unwrap();
        outputs.last_mut().unwrap().1.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_renamed_continuation_extracts_under_the_first_name() {
    let data = noise(1, 30_000);
    for version in VERSIONS {
        for stored in [true, false] {
            for renamed in [b"DATA.BIN".as_slice(), b"another/longer-name.bin"] {
                let mut volumes = build_set(version, stored, b"data.bin", &data);
                rename_continuation(&mut volumes[1], renamed);

                let extracted = extract(&volumes).unwrap_or_else(|error| {
                    panic!("{version:?} stored={stored} {renamed:?}: {error}")
                });

                assert_eq!(
                    extracted,
                    [(b"data.bin".to_vec(), data.clone())],
                    "{version:?} stored={stored} {renamed:?}"
                );
            }
        }
    }
}

#[test]
fn a_continuation_spliced_from_another_member_is_refused() {
    let data = noise(1, 30_000);
    for version in VERSIONS {
        for stored in [true, false] {
            let other_size_set = build_set(version, stored, b"other.bin", &noise(2, 30_001));
            let mut volumes = build_set(version, stored, b"data.bin", &data);
            volumes[1] = other_size_set[1].clone();
            let error = extract(&volumes).unwrap_err().to_string();
            assert!(
                error.contains("unpacked size changed"),
                "{version:?} stored={stored}: {error}"
            );

            let same_size_set = build_set(version, stored, b"else.bin", &noise(2, 30_000));
            let mut volumes = build_set(version, stored, b"data.bin", &data);
            volumes[1] = same_size_set[1].clone();
            let error = extract(&volumes).unwrap_err();
            assert!(
                matches!(error.kind(), rars::ErrorKind::ChecksumMismatch),
                "{version:?} stored={stored}: {error}"
            );
        }
    }
}

#[test]
fn a_rar_made_set_with_a_renamed_continuation_extracts_under_the_first_name() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar50");
    let volumes: Vec<Vec<u8>> = [
        "renamed_continuation.part01.rar",
        "renamed_continuation.part02.rar",
    ]
    .iter()
    .map(|name| std::fs::read(fixtures.join(name)).unwrap())
    .collect();
    let payload: String = (0..600)
        .map(|i| {
            format!(
                "line {i}: split continuation fixture payload {}\n",
                i * i % 977
            )
        })
        .collect();

    let extracted = extract(&volumes).unwrap();

    assert_eq!(extracted, [(b"payload.txt".to_vec(), payload.into_bytes())]);
}
