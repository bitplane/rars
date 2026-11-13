use super::*;
use crate::streaming::SourceFactory;
use crate::ArchiveReader;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct Repeat {
    len: u64,
    reads: Arc<AtomicU64>,
    byte: fn(u64) -> u8,
}

fn ramp(pos: u64) -> u8 {
    (pos % 251) as u8
}

struct RepeatReader {
    pos: u64,
    len: u64,
    reads: Arc<AtomicU64>,
    byte: fn(u64) -> u8,
}

impl Read for RepeatReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let n = buf.len().min((self.len - self.pos) as usize);
        for (offset, byte) in buf[..n].iter_mut().enumerate() {
            *byte = (self.byte)(self.pos + offset as u64);
        }
        self.pos += n as u64;
        self.reads.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl Seek for RepeatReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::Current(delta) => self.pos as i64 + delta,
            SeekFrom::End(delta) => self.len as i64 + delta,
        };
        if next < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

impl SourceFactory for Repeat {
    fn len(&self) -> crate::Result<u64> {
        Ok(self.len)
    }
    fn open(&self) -> crate::Result<Box<dyn crate::EntryReader>> {
        Ok(Box::new(RepeatReader {
            pos: 0,
            len: self.len,
            reads: Arc::clone(&self.reads),
            byte: self.byte,
        }))
    }
}

fn options(version: crate::ArchiveVersion) -> WriterOptions {
    WriterOptions::new(version, crate::FeatureSet::store_only())
}

fn tempfile_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rars-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Free bytes on the temp filesystem, from POSIX `df -kP`. `None` if `df`
/// cannot be read, so the large-file tests still run.
fn available_temp_bytes() -> Option<u64> {
    let output = std::process::Command::new("df")
        .args(["-kP"])
        .arg(std::env::temp_dir())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let available_kib = text.lines().nth(1)?.split_whitespace().nth(3)?;
    available_kib
        .parse::<u64>()
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

/// Hosted CI disks are smaller than these archives. Skip only when `df`
/// reports too little free space.
fn skip_unless_temp_can_hold(bytes: u64) -> bool {
    match available_temp_bytes() {
        Some(free) if free < bytes => {
            eprintln!("skipping large-file test: {free} bytes free in the temp dir, need {bytes}");
            true
        }
        _ => false,
    }
}

#[test]
fn rar29_plain_archive_round_trips_a_member_over_four_gibibytes() {
    let len = u64::from(u32::MAX) + 4096;
    if skip_unless_temp_can_hold(len + 64 * 1024 * 1024) {
        return;
    }
    let source = EntrySource::from_factory(Repeat {
        len,
        reads: Arc::new(AtomicU64::new(0)),
        byte: ramp,
    });
    let entry = StreamingEntry::new(b"big.bin".to_vec(), source);
    let path = tempfile_path("over4g");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            options(crate::ArchiveVersion::Rar30),
            crate::MemberCoding::Stored,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    let archive = ArchiveReader::read_path(&path).unwrap();
    let crate::Archive::Rar15To40(parsed) = &archive else {
        panic!("expected a legacy archive");
    };
    let file = parsed.blocks.iter().find_map(|block| match block {
        super::super::Block::File(file) => Some(file),
        _ => None,
    });
    let file = file.expect("archive has a file");
    assert_ne!(file.block.flags & super::super::FHD_LARGE, 0);
    assert_eq!(file.unp_size, len);
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    archive
        .extract_to(None, {
            let mismatch = Arc::clone(&mismatch);
            let seen = Arc::clone(&seen);
            move |_| {
                Ok(Box::new(CheckWriter {
                    pos: 0,
                    mismatch: Arc::clone(&mismatch),
                    seen: Arc::clone(&seen),
                    byte: ramp,
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(
        mismatch.lock().expect("check lock").is_none(),
        "byte mismatch at {:?}",
        mismatch.lock().expect("check lock")
    );
    let _ = std::fs::remove_file(&path);
}

struct CheckWriter {
    pos: u64,
    mismatch: Arc<Mutex<Option<u64>>>,
    seen: Arc<AtomicU64>,
    byte: fn(u64) -> u8,
}

impl Write for CheckWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut mismatch = self.mismatch.lock().expect("check lock");
        for (offset, byte) in buf.iter().enumerate() {
            let at = self.pos + offset as u64;
            if *byte != (self.byte)(at) && mismatch.is_none() {
                *mismatch = Some(at);
            }
        }
        drop(mismatch);
        self.pos += buf.len() as u64;
        self.seen.store(self.pos, Ordering::Relaxed);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn several_stored_members_share_one_legacy_volume_set() {
    let first = vec![7u8; 20_000];
    let second = vec![9u8; 80_000];
    let entries = [
        StreamingEntry::new(b"a.bin".to_vec(), EntrySource::from_bytes(first.clone())),
        StreamingEntry::new(b"b.bin".to_vec(), EntrySource::from_bytes(second.clone())),
    ];
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    write_stored_entries_to(
        &entries,
        options(crate::ArchiveVersion::Rar30),
        30_000,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    let volumes = sink.take();
    assert!(
        volumes.len() >= 3,
        "the second member has to cross a boundary"
    );
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| ArchiveReader::read(volume).unwrap())
        .collect();
    let parts = Arc::new(Mutex::new(Vec::new()));
    crate::extract_volumes_to(&archives, None, {
        let parts = Arc::clone(&parts);
        move |_| {
            Ok(Box::new(PartWriter {
                buf: Vec::new(),
                out: Arc::clone(&parts),
            }) as Box<dyn Write>)
        }
    })
    .unwrap();
    let parts = parts.lock().expect("parts");
    assert_eq!(parts.as_slice(), &[first, second]);
}

struct PartWriter {
    buf: Vec<u8>,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Drop for PartWriter {
    fn drop(&mut self) {
        self.out
            .lock()
            .expect("parts")
            .push(std::mem::take(&mut self.buf));
    }
}

impl Write for PartWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn streamed_rar29_compression_round_trips_without_reading_the_member_twice_up_front() {
    let len = 256 * 1024 + 100;
    let reads = Arc::new(AtomicU64::new(0));
    let source = EntrySource::from_factory(Repeat {
        len,
        reads: Arc::clone(&reads),
        byte: ramp,
    });
    let entry = StreamingEntry::new(b"stream.bin".to_vec(), source);
    let path = tempfile_path("stream");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
                .with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    // Sample plus one encode pass. Loading the member to choose a method and
    // again to encode would read it three times (sample is a prefix of the
    // encode pass, so two full passes is the failure).
    let total_reads = reads.load(Ordering::Relaxed);
    assert!(
        total_reads < len * 2,
        "reader supplied {total_reads} bytes for a {len}-byte member"
    );
    let archive = ArchiveReader::read_path(&path).unwrap();
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    archive
        .extract_to(None, {
            let mismatch = Arc::clone(&mismatch);
            let seen = Arc::clone(&seen);
            move |_| {
                Ok(Box::new(CheckWriter {
                    pos: 0,
                    mismatch: Arc::clone(&mismatch),
                    seen: Arc::clone(&seen),
                    byte: ramp,
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(
        mismatch.lock().expect("check lock").is_none(),
        "byte mismatch at {:?}",
        mismatch.lock().expect("check lock")
    );
    let _ = std::fs::remove_file(path);
}

fn noise(pos: u64) -> u8 {
    let mut z = pos.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) as u8
}

fn semi(pos: u64) -> u8 {
    let page = (pos / 4096) as u8;
    let within = (pos % 64) as u8;
    page.wrapping_mul(19) ^ within.wrapping_mul(3)
}

fn pattern_source(len: u64, byte: fn(u64) -> u8) -> (EntrySource, Arc<AtomicU64>) {
    let reads = Arc::new(AtomicU64::new(0));
    let source = EntrySource::from_factory(Repeat {
        len,
        reads: Arc::clone(&reads),
        byte,
    });
    (source, reads)
}

fn check_extract(archive: &crate::Archive, len: u64, byte: fn(u64) -> u8) {
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    archive
        .extract_to(None, {
            let mismatch = Arc::clone(&mismatch);
            let seen = Arc::clone(&seen);
            move |_| {
                Ok(Box::new(CheckWriter {
                    pos: 0,
                    mismatch: Arc::clone(&mismatch),
                    seen: Arc::clone(&seen),
                    byte,
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(mismatch.lock().expect("check lock").is_none());
}

fn file_method(archive: &crate::Archive) -> u8 {
    let crate::Archive::Rar15To40(parsed) = archive else {
        panic!("expected a legacy archive");
    };
    parsed
        .blocks
        .iter()
        .find_map(|block| match block {
            super::super::Block::File(file) => Some(file.method),
            _ => None,
        })
        .expect("file")
}

struct BytesRepeat {
    data: Vec<u8>,
    reads: Arc<AtomicU64>,
}

struct BytesRepeatReader {
    data: Vec<u8>,
    pos: u64,
    reads: Arc<AtomicU64>,
}

impl Read for BytesRepeatReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos as usize >= self.data.len() {
            return Ok(0);
        }
        let start = self.pos as usize;
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        self.reads.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl Seek for BytesRepeatReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::Current(delta) => self.pos as i64 + delta,
            SeekFrom::End(delta) => self.data.len() as i64 + delta,
        };
        if next < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

impl SourceFactory for BytesRepeat {
    fn len(&self) -> crate::Result<u64> {
        Ok(self.data.len() as u64)
    }
    fn open(&self) -> crate::Result<Box<dyn crate::EntryReader>> {
        Ok(Box::new(BytesRepeatReader {
            data: self.data.clone(),
            pos: 0,
            reads: Arc::clone(&self.reads),
        }))
    }
}

fn calls_to_fixed_addresses(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491u32;
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        if state.is_multiple_of(11) {
            let target = 0x4000u32 + (state >> 28) * 0x400;
            data.push(0xe8);
            data.extend_from_slice(&target.to_le_bytes());
        } else {
            data.extend_from_slice(&[0x48, 0x89, (state >> 16) as u8, 0xe5]);
        }
    }
    data.truncate(len);
    data
}

/// Filter programs are bit-packed, so the bytecode is not on a byte boundary.
fn contains_unaligned(data: &[u8], needle: &[u8]) -> bool {
    let total_bits = data.len().saturating_mul(8);
    let need_bits = needle.len().saturating_mul(8);
    if needle.is_empty() || total_bits < need_bits {
        return false;
    }
    for bit in 0..=total_bits - need_bits {
        let matched = needle.iter().enumerate().all(|(index, expected)| {
            let at = bit + index * 8;
            let byte = at / 8;
            let shift = at % 8;
            let got = if shift == 0 {
                data[byte]
            } else if byte + 1 < data.len() {
                (data[byte] << shift) | (data[byte + 1] >> (8 - shift))
            } else {
                return false;
            };
            got == *expected
        });
        if matched {
            return true;
        }
    }
    false
}

#[test]
fn streamed_member_chooses_a_filter_from_the_sample() {
    let data = calls_to_fixed_addresses(256 * 1024 + 64);
    let reads = Arc::new(AtomicU64::new(0));
    let counted = EntrySource::from_factory(BytesRepeat {
        data: data.clone(),
        reads: Arc::clone(&reads),
    });
    let entry = StreamingEntry::new(b"code.bin".to_vec(), counted);
    let path = tempfile_path("filter");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
                .with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    assert!(reads.load(Ordering::Relaxed) < data.len() as u64 * 2);
    let packed = std::fs::read(&path).unwrap();
    let delta = [0x2f, 0x01, 0x9a, 0x41];
    let e8 = [0x97, 0x1b, 0x01, 0x28];
    assert!(
        contains_unaligned(&packed, &delta) || contains_unaligned(&packed, &e8),
        "sample should have selected a RAR 2.9 filter"
    );
    let archive = ArchiveReader::read_path(&path).unwrap();
    assert_ne!(file_method(&archive), 0x30);
    let got = archive.read_member(b"code.bin", None).unwrap().unwrap();
    assert_eq!(got, data);
    let _ = std::fs::remove_file(path);
}

#[test]
fn streamed_member_stores_when_the_sample_does_not_shrink() {
    let len = 256 * 1024 + 32;
    let (source, _) = pattern_source(len, noise);
    let entry = StreamingEntry::new(b"noise.bin".to_vec(), source);
    let path = tempfile_path("noise");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
                .with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    let archive = ArchiveReader::read_path(&path).unwrap();
    assert_eq!(file_method(&archive), 0x30);
    check_extract(&archive, len, noise);
    let _ = std::fs::remove_file(path);
}

#[test]
fn streamed_password_member_stores_noise_encrypted() {
    let len = 80 * 1024;
    let (source, _) = pattern_source(len, noise);
    let entry = StreamingEntry::new(b"noise.bin".to_vec(), source).with_password(b"secret");
    let path = tempfile_path("pw-noise");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
                .with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let crate::Archive::Rar15To40(parsed) = &archive else {
        panic!("expected a legacy archive");
    };
    let file = parsed
        .blocks
        .iter()
        .find_map(|block| match block {
            super::super::Block::File(file) => Some(file),
            _ => None,
        })
        .expect("file");
    assert_eq!(file.method, 0x30);
    assert_ne!(file.block.flags & super::super::FHD_PASSWORD, 0);
    assert_ne!(file.block.flags & super::super::FHD_SALT, 0);
    assert!(file.salt.is_some());
    let packed = &bytes[file.packed_range.clone()];
    let mut plain = vec![0u8; 32];
    for (index, byte) in plain.iter_mut().enumerate() {
        *byte = noise(index as u64);
    }
    assert_ne!(&packed[..plain.len()], plain.as_slice());
    assert!(archive
        .extract_to(None, |_| Ok(Box::new(std::io::sink())))
        .is_err());
    assert!(archive
        .extract_to(Some(b"nope"), |_| Ok(Box::new(std::io::sink())))
        .is_err());
    check_extract_password(&archive, len, noise, b"secret");
    let _ = std::fs::remove_file(path);
}

fn check_extract_password(
    archive: &crate::Archive,
    len: u64,
    byte: fn(u64) -> u8,
    password: &[u8],
) {
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    archive
        .extract_to(Some(password), {
            let mismatch = Arc::clone(&mismatch);
            let seen = Arc::clone(&seen);
            move |_| {
                Ok(Box::new(CheckWriter {
                    pos: 0,
                    mismatch: Arc::clone(&mismatch),
                    seen: Arc::clone(&seen),
                    byte,
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(mismatch.lock().expect("check lock").is_none());
}

#[test]
fn password_protected_rar29_member_streams() {
    let len = 300 * 1024;
    let (source, reads) = pattern_source(len, ramp);
    let entry = StreamingEntry::new(b"secret.bin".to_vec(), source).with_password(b"secret");
    let path = tempfile_path("pw");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
                .with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    assert!(reads.load(Ordering::Relaxed) < len * 2);
    let archive = ArchiveReader::read_path(&path).unwrap();
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    archive
        .extract_to(Some(b"secret"), {
            let mismatch = Arc::clone(&mismatch);
            let seen = Arc::clone(&seen);
            move |_| {
                Ok(Box::new(CheckWriter {
                    pos: 0,
                    mismatch: Arc::clone(&mismatch),
                    seen: Arc::clone(&seen),
                    byte: ramp,
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(mismatch.lock().expect("check lock").is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn solid_rar29_members_stream() {
    let len = 300 * 1024;
    let (first, reads_a) = pattern_source(len, ramp);
    let (second, reads_b) = pattern_source(len, ramp);
    let entries = [
        StreamingEntry::new(b"a.bin".to_vec(), first),
        StreamingEntry::new(b"b.bin".to_vec(), second),
    ];
    let features = crate::FeatureSet {
        solid: true,
        ..crate::FeatureSet::default()
    };
    let path = tempfile_path("solid");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &entries,
            WriterOptions::new(crate::ArchiveVersion::Rar30, features).with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    assert!(reads_a.load(Ordering::Relaxed) < len * 2);
    assert!(reads_b.load(Ordering::Relaxed) < len * 2);
    let archive = ArchiveReader::read_path(&path).unwrap();
    let parts = Arc::new(Mutex::new(Vec::new()));
    archive
        .extract_to(None, {
            let parts = Arc::clone(&parts);
            move |_| {
                Ok(Box::new(PartWriter {
                    buf: Vec::new(),
                    out: Arc::clone(&parts),
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    let parts = parts.lock().expect("parts");
    assert_eq!(parts.len(), 2);
    assert!(parts[0]
        .iter()
        .enumerate()
        .all(|(i, byte)| *byte == ramp(i as u64)));
    assert!(parts[1]
        .iter()
        .enumerate()
        .all(|(i, byte)| *byte == ramp(i as u64)));
    let _ = std::fs::remove_file(path);
}

#[test]
fn solid_stream_stores_noise_and_the_next_member_still_extracts() {
    let len = 80 * 1024;
    let (ramp_a, _) = pattern_source(len, ramp);
    let (middle, _) = pattern_source(len, noise);
    let (ramp_b, _) = pattern_source(len, ramp);
    let entries = [
        StreamingEntry::new(b"a.bin".to_vec(), ramp_a),
        StreamingEntry::new(b"b.bin".to_vec(), middle),
        StreamingEntry::new(b"c.bin".to_vec(), ramp_b),
    ];
    let features = crate::FeatureSet {
        solid: true,
        ..crate::FeatureSet::default()
    };
    let path = tempfile_path("solid-store");
    {
        let mut out = std::fs::File::create(&path).unwrap();
        write_streaming_archive_to(
            &entries,
            WriterOptions::new(crate::ArchiveVersion::Rar30, features).with_compression_level(1),
            crate::MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
    }
    let archive = ArchiveReader::read_path(&path).unwrap();
    let methods = file_methods(&archive);
    assert_eq!(methods.len(), 3, "{methods:?}");
    assert_eq!(methods[1], 0x30, "noise must be stored, got {methods:?}");
    assert_ne!(methods[0], 0x30, "{methods:?}");
    assert_ne!(methods[2], 0x30, "{methods:?}");
    let parts = Arc::new(Mutex::new(Vec::new()));
    archive
        .extract_to(None, {
            let parts = Arc::clone(&parts);
            move |_| {
                Ok(Box::new(PartWriter {
                    buf: Vec::new(),
                    out: Arc::clone(&parts),
                }) as Box<dyn Write>)
            }
        })
        .unwrap();
    let parts = parts.lock().expect("parts");
    assert_eq!(parts.len(), 3);
    let patterns = [ramp, noise, ramp];
    for (part, byte) in parts.iter().zip(patterns) {
        assert_eq!(part.len() as u64, len);
        assert!(part
            .iter()
            .enumerate()
            .all(|(i, value)| *value == byte(i as u64)));
    }
    let _ = std::fs::remove_file(path);
}

fn file_methods(archive: &crate::Archive) -> Vec<u8> {
    let crate::Archive::Rar15To40(parsed) = archive else {
        panic!("expected a legacy archive");
    };
    parsed
        .blocks
        .iter()
        .filter_map(|block| match block {
            super::super::Block::File(file) => Some(file.method),
            _ => None,
        })
        .collect()
}

struct EventSink {
    volumes: Arc<Mutex<Vec<Vec<u8>>>>,
    events: Vec<&'static str>,
}

impl crate::volume_sink::VolumeSink for EventSink {
    fn start_volume(
        &mut self,
        index: u64,
    ) -> crate::Result<Box<dyn crate::volume_sink::VolumeOutput>> {
        let mut volumes = self.volumes.lock().expect("volumes");
        assert_eq!(index as usize, volumes.len());
        volumes.push(Vec::new());
        drop(volumes);
        self.events.push("start");
        Ok(Box::new(EventVolume {
            volumes: Arc::clone(&self.volumes),
            index: index as usize,
            position: 0,
        }))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> crate::Result<()> {
        let volumes = self.volumes.lock().expect("volumes");
        assert_eq!(volumes[index as usize].len() as u64, len);
        drop(volumes);
        self.events.push("finish");
        Ok(())
    }
}

struct EventVolume {
    volumes: Arc<Mutex<Vec<Vec<u8>>>>,
    index: usize,
    position: usize,
}

impl Write for EventVolume {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut volumes = self.volumes.lock().expect("volumes");
        let volume = &mut volumes[self.index];
        let overlap = buf.len().min(volume.len().saturating_sub(self.position));
        if self.position < volume.len() {
            volume[self.position..self.position + overlap].copy_from_slice(&buf[..overlap]);
        }
        volume.extend_from_slice(&buf[overlap..]);
        self.position += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for EventVolume {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let len = self.volumes.lock().expect("volumes")[self.index].len();
        self.position = crate::volume_sink::seek_within(self.position, len, from)?;
        Ok(self.position as u64)
    }
}

#[test]
fn compressed_volumes_are_handed_to_the_sink_as_they_fill() {
    let len = 512 * 1024;
    let (source, reads) = pattern_source(len, semi);
    let entries = [StreamingEntry::new(b"wide.bin".to_vec(), source)];
    let mut sink = EventSink {
        volumes: Arc::new(Mutex::new(Vec::new())),
        events: Vec::new(),
    };
    write_compressed_entries_to(
        &entries,
        WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
            .with_compression_level(1),
        2_500,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    assert!(reads.load(Ordering::Relaxed) < len * 2);
    let finishes: Vec<_> = sink
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| **event == "finish")
        .map(|(index, _)| index)
        .collect();
    assert!(
        finishes.len() >= 2,
        "events {:?}, volumes {}",
        sink.events,
        sink.volumes.lock().expect("volumes").len()
    );
    let first_finish = finishes[0];
    let second_start = sink
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| **event == "start")
        .nth(1)
        .map(|(index, _)| index)
        .expect("a second volume");
    assert!(
        first_finish < second_start,
        "the first volume must be finished before the next one starts: {:?}",
        sink.events
    );
    let volumes = sink.volumes.lock().expect("volumes").clone();
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| ArchiveReader::read(volume).unwrap())
        .collect();
    let parts = Arc::new(Mutex::new(Vec::new()));
    crate::extract_volumes_to(&archives, None, {
        let parts = Arc::clone(&parts);
        move |_| {
            Ok(Box::new(PartWriter {
                buf: Vec::new(),
                out: Arc::clone(&parts),
            }) as Box<dyn Write>)
        }
    })
    .unwrap();
    let parts = parts.lock().expect("parts");
    assert_eq!(parts.len(), 1);
    assert!(parts[0]
        .iter()
        .enumerate()
        .all(|(i, byte)| *byte == semi(i as u64)));
}

#[test]
fn several_compressed_members_share_one_legacy_volume_set() {
    let (short, _) = pattern_source(20_000, ramp);
    let (long, reads) = pattern_source(512 * 1024, semi);
    let entries = [
        StreamingEntry::new(b"short.bin".to_vec(), short),
        StreamingEntry::new(b"long.bin".to_vec(), long),
    ];
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    write_compressed_entries_to(
        &entries,
        WriterOptions::new(crate::ArchiveVersion::Rar30, crate::FeatureSet::default())
            .with_compression_level(1),
        1_500,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    assert!(reads.load(Ordering::Relaxed) < 512 * 1024 * 2);
    let volumes = sink.take();
    assert!(
        volumes.len() >= 2,
        "the long member has to cross a boundary"
    );
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| ArchiveReader::read(volume).unwrap())
        .collect();
    let parts = Arc::new(Mutex::new(Vec::new()));
    crate::extract_volumes_to(&archives, None, {
        let parts = Arc::clone(&parts);
        move |_| {
            Ok(Box::new(PartWriter {
                buf: Vec::new(),
                out: Arc::clone(&parts),
            }) as Box<dyn Write>)
        }
    })
    .unwrap();
    let parts = parts.lock().expect("parts");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].len(), 20_000);
    assert!(parts[1]
        .iter()
        .enumerate()
        .all(|(i, byte)| *byte == semi(i as u64)));
}

fn rss_kib() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("rss")
        .parse()
        .expect("rss number")
}

struct DiskSink {
    dir: std::path::PathBuf,
    paths: Vec<std::path::PathBuf>,
}

impl Drop for DiskSink {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

impl crate::volume_sink::VolumeSink for DiskSink {
    fn start_volume(
        &mut self,
        index: u64,
    ) -> crate::Result<Box<dyn crate::volume_sink::VolumeOutput>> {
        let path = self.dir.join(format!("part{index}"));
        let file = std::fs::File::create(&path)?;
        self.paths.push(path);
        Ok(Box::new(file))
    }
}

#[test]
fn stored_legacy_volume_set_splits_twenty_one_gigabytes_in_bounded_memory() {
    let len = 21 * 1024 * 1024 * 1024;
    if skip_unless_temp_can_hold(len + 1024 * 1024 * 1024) {
        return;
    }
    let (source, _) = pattern_source(len, ramp);
    let entry = StreamingEntry::new(b"huge.bin".to_vec(), source);
    let dir = tempfile_path("vol21");
    std::fs::create_dir(&dir).unwrap();
    let mut sink = DiskSink {
        dir: dir.clone(),
        paths: Vec::new(),
    };
    write_stored_volumes_to(
        &entry,
        options(crate::ArchiveVersion::Rar30),
        1024 * 1024 * 1024,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    let rss = rss_kib();
    let line = format!(
        "21GB stored volume rss_kib={rss} volumes={}",
        sink.paths.len()
    );
    println!("{line}");
    eprintln!("{line}");
    let _ = std::fs::write(std::env::temp_dir().join("rars-21gb-rss.txt"), &line);
    assert!(
        rss < 2 * 1024 * 1024,
        "rss {rss} KiB is not bounded for a 21 GiB split"
    );
    assert!(sink.paths.len() > 1);
    let archives: Vec<_> = sink
        .paths
        .iter()
        .map(|path| ArchiveReader::read_path(path).unwrap())
        .collect();
    let mismatch = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicU64::new(0));
    crate::extract_volumes_to(&archives, None, {
        let mismatch = Arc::clone(&mismatch);
        let seen = Arc::clone(&seen);
        move |_| {
            Ok(Box::new(CheckWriter {
                pos: 0,
                mismatch: Arc::clone(&mismatch),
                seen: Arc::clone(&seen),
                byte: ramp,
            }) as Box<dyn Write>)
        }
    })
    .unwrap();
    assert_eq!(seen.load(Ordering::Relaxed), len);
    assert!(mismatch.lock().expect("check lock").is_none());
}
