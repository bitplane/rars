use super::{write_stored_volumes_to, StreamingEntry, WriterOptions};
use crate::crc32::Crc32;
use crate::volume_sink::{VolumeOutput, VolumeSink};
use crate::{ArchiveVersion, FeatureSet, Result, WriterResources};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Just past 4 GiB, so the header needs the high size fields, without a 21 GiB copy.
const SIZE: u64 = (4 << 30) + 4096;
const VOLUME: usize = 8 << 20;
const MARKER: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_LARGE: u16 = 0x0100;
const FILE_HEAD: u8 = 0x74;

struct Fragment {
    flags: u16,
    packed: u64,
    unpacked: u64,
    file_crc: u32,
    unp_ver: u8,
    method: u8,
}

/// Keeps one volume file and the file headers. The payload is not retained.
struct HeaderSink {
    path: PathBuf,
    file: File,
    fragments: Vec<Fragment>,
}

impl HeaderSink {
    fn create(dir: &Path) -> std::io::Result<Self> {
        let path = dir.join("volume");
        let file = File::create(&path)?;
        Ok(Self {
            path,
            file,
            fragments: Vec::new(),
        })
    }
}

impl VolumeSink for HeaderSink {
    fn start_volume(&mut self, _index: u64) -> Result<Box<dyn VolumeOutput>> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(Box::new(self.file.try_clone()?))
    }

    fn finish_volume(&mut self, _index: u64, len: u64) -> Result<()> {
        let mut file = File::open(&self.path)?;
        let take = (len as usize).min(8192);
        let mut bytes = vec![0u8; take];
        file.read_exact(&mut bytes)?;
        self.fragments.push(parse_fragment(&bytes));
        Ok(())
    }
}

fn parse_fragment(bytes: &[u8]) -> Fragment {
    let at = bytes
        .windows(b"huge.bin".len())
        .position(|window| window == b"huge.bin")
        .expect("file header should carry the member name");
    let start = at - 40;
    assert_eq!(
        bytes[start + 2],
        FILE_HEAD,
        "name should sit in a file header"
    );
    let flags = u16::from_le_bytes(bytes[start + 3..start + 5].try_into().unwrap());
    assert_ne!(flags & FHD_LARGE, 0, "a member over 4 GiB sets FHD_LARGE");
    let low = |offset: usize| {
        u32::from_le_bytes(
            bytes[start + offset..start + offset + 4]
                .try_into()
                .unwrap(),
        ) as u64
    };
    let pack_low = low(7);
    let unp_low = low(11);
    let file_crc = low(16) as u32;
    let high_pack = low(32);
    let high_unp = low(36);
    Fragment {
        flags,
        packed: (high_pack << 32) | pack_low,
        unpacked: (high_unp << 32) | unp_low,
        file_crc,
        unp_ver: bytes[start + 24],
        method: bytes[start + 25],
    }
}

fn sparse_member(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("huge.bin");
    let mut file = File::create(&path)?;
    file.set_len(SIZE)?;
    file.seek(SeekFrom::End(-(MARKER.len() as i64)))?;
    file.write_all(&MARKER)?;
    Ok(path)
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/legacy-large-volume");
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

#[test]
fn rar15_volume_still_refuses_a_member_over_4_gib() {
    let source = crate::streaming::EntrySource::from_opener(SIZE, || {
        panic!("RAR 1.5 should refuse before reading the member");
    });
    let entry = StreamingEntry::new(b"huge.bin".to_vec(), source);
    let dir = Scratch::new();
    let mut sink = HeaderSink::create(&dir).unwrap();
    let error = write_stored_volumes_to(
        &entry,
        WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only()),
        VOLUME,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.to_string().contains("RAR 1.5"),
        "the refusal should name the format: {error}"
    );
}

#[test]
fn stored_volume_set_splits_a_sparse_member_over_4_gib() {
    let dir = Scratch::new();
    let path = sparse_member(&dir).unwrap();
    let entry = StreamingEntry::new(
        b"huge.bin".to_vec(),
        crate::streaming::EntrySource::from_path(&path),
    );
    let mut sink = HeaderSink::create(&dir).unwrap();
    write_stored_volumes_to(
        &entry,
        WriterOptions::new(ArchiveVersion::Rar30, FeatureSet::store_only()),
        VOLUME,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    let rss = rss_kib();
    let fragments = &sink.fragments;
    assert!(
        fragments.len() > 1,
        "the member should cross a volume boundary"
    );
    assert!(
        rss < 1024 * 1024,
        "rss {rss} KiB is not bounded for a sparse member over 4 GiB"
    );
    let packed: u64 = fragments.iter().map(|fragment| fragment.packed).sum();
    assert_eq!(packed, SIZE);
    for fragment in fragments {
        assert_eq!(fragment.unpacked, SIZE);
        assert_eq!(fragment.method, 0x30);
        assert_eq!(fragment.unp_ver, 29);
    }
    assert_eq!(fragments[0].flags & FHD_SPLIT_BEFORE, 0);
    assert_ne!(fragments[0].flags & FHD_SPLIT_AFTER, 0);
    let last = fragments.last().unwrap();
    assert_ne!(last.flags & FHD_SPLIT_BEFORE, 0);
    assert_eq!(last.flags & FHD_SPLIT_AFTER, 0);
    for fragment in &fragments[1..fragments.len() - 1] {
        assert_ne!(fragment.flags & FHD_SPLIT_BEFORE, 0);
        assert_ne!(fragment.flags & FHD_SPLIT_AFTER, 0);
    }
    let mut crc = Crc32::new();
    crc.update_zeroes(SIZE - MARKER.len() as u64);
    crc.update(&MARKER);
    assert_eq!(last.file_crc, crc.finish());
}
