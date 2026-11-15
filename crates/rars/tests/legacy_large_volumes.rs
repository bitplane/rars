#![cfg(feature = "write")]

use rars::crc32::Crc32;
use rars::rar15_40::{
    write_stored_volumes_to, Archive, Block, EntrySource, StreamingEntry, VolumeOutput, VolumeSink,
    WriterOptions,
};
use rars::{ArchiveVersion, FeatureSet, WriterResources};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[path = "support/scratch.rs"]
mod scratch;

const SIZE: u64 = (4 << 30) + 4099;
const VOLUME_SIZE: usize = 1 << 30;

struct Zeroes {
    position: u64,
}

impl Read for Zeroes {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = (SIZE - self.position).min(buffer.len() as u64) as usize;
        buffer[..count].fill(0);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Zeroes {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => SIZE.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.position.saturating_add_signed(delta),
        }
        .min(SIZE);
        Ok(self.position)
    }
}

struct Holes(File);

impl Write for Holes {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        static ZEROES: [u8; 1 << 16] = [0; 1 << 16];
        if buffer
            .chunks(ZEROES.len())
            .all(|chunk| chunk == &ZEROES[..chunk.len()])
        {
            self.0.seek(SeekFrom::Current(buffer.len() as i64))?;
            return Ok(buffer.len());
        }
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Seek for Holes {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}

struct SparseFiles {
    dir: PathBuf,
    paths: Vec<PathBuf>,
}

impl VolumeSink for SparseFiles {
    fn start_volume(&mut self, index: u64) -> rars::Result<Box<dyn VolumeOutput>> {
        let path = self.dir.join(format!("big.{index:03}"));
        let file = File::create(&path)?;
        self.paths.push(path);
        Ok(Box::new(Holes(file)))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> rars::Result<()> {
        File::options()
            .write(true)
            .open(&self.paths[index as usize])?
            .set_len(len)?;
        Ok(())
    }
}

fn zero_crc(len: u64) -> u32 {
    let mut crc = Crc32::new();
    crc.update_zeroes(len);
    crc.finish()
}

fn file_crc(path: &Path, len: u64) -> u32 {
    let mut file = File::open(path).unwrap().take(len);
    let mut crc = Crc32::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            return crc.finish();
        }
        crc.update(&buffer[..read]);
    }
}

#[test]
fn a_stored_member_over_4_gib_splits_across_volumes_with_large_headers() {
    let dir = scratch::case("legacy-large-volumes");
    let mut sink = SparseFiles {
        dir: dir.to_path_buf(),
        paths: Vec::new(),
    };
    let source = EntrySource::from_opener(SIZE, || Ok(Box::new(Zeroes { position: 0 })));
    write_stored_volumes_to(
        &StreamingEntry::new(b"big.bin".to_vec(), source),
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        VOLUME_SIZE,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();

    assert_eq!(sink.paths.len(), 5);
    let last = sink.paths.len() - 1;
    let mut packed_total = 0;
    for (index, path) in sink.paths.iter().enumerate() {
        assert!(std::fs::metadata(path).unwrap().len() <= VOLUME_SIZE as u64);
        let archive = Archive::parse_path(path).unwrap();
        let files: Vec<_> = archive.files().collect();
        let [file] = files.as_slice() else {
            panic!("volume {index} has {} file headers", files.len());
        };
        assert_eq!(file.unp_size, SIZE, "volume {index}");
        assert_eq!(file.is_split_before(), index > 0, "volume {index}");
        assert_eq!(file.is_split_after(), index < last, "volume {index}");
        let expected_crc = if index < last {
            zero_crc(file.pack_size)
        } else {
            zero_crc(SIZE)
        };
        assert_eq!(file.file_crc, expected_crc, "volume {index}");
        packed_total += file.pack_size;

        let end = archive
            .blocks
            .iter()
            .find_map(|block| match block {
                Block::End(end) => Some(end),
                _ => None,
            })
            .unwrap();
        assert_eq!(end.has_next_volume(), index < last, "volume {index}");
        assert_eq!(end.volume_number, Some(index as u16));
        assert_eq!(
            end.data_crc,
            Some(file_crc(path, end.block.offset as u64)),
            "volume {index}"
        );
    }
    assert_eq!(packed_total, SIZE);
}
