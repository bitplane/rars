use crate::error::{Error, Result};
use crate::io_util::read_exact_at;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};

trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

pub(crate) struct ReaderSource {
    reader: Mutex<Box<dyn ReadSeek>>,
    len: usize,
}

impl std::fmt::Debug for ReaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderSource")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl ReaderSource {
    pub(crate) fn new(mut reader: impl Read + Seek + Send + 'static) -> Result<Arc<Self>> {
        let len = usize::try_from(reader.seek(SeekFrom::End(0))?)
            .map_err(|_| Error::InvalidHeader("archive size overflows host address size"))?;
        Ok(Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            len,
        }))
    }

    pub(crate) fn cursor(self: &Arc<Self>) -> SourceCursor {
        SourceCursor {
            source: self.clone(),
            position: 0,
        }
    }
}

pub(crate) struct SourceCursor {
    source: Arc<ReaderSource>,
    position: u64,
}

impl Read for SourceCursor {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = (self.source.len as u64).saturating_sub(self.position);
        let count = bytes.len().min(remaining as usize);
        if count == 0 {
            return Ok(0);
        }
        let mut reader = self
            .source
            .reader
            .lock()
            .map_err(|_| std::io::Error::other("archive reader lock poisoned"))?;
        // The seek and read share one lock; sibling cursors never share a position.
        reader.seek(SeekFrom::Start(self.position))?;
        let count = reader.read(&mut bytes[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let position = match from {
            SeekFrom::Start(position) => position as i128,
            SeekFrom::Current(offset) => self.position as i128 + offset as i128,
            SeekFrom::End(offset) => self.source.len as i128 + offset as i128,
        };
        self.position = u64::try_from(position)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}

/// Handles kept open across all file-backed volumes, so huge sets stay under the fd limit.
const OPEN_FILE_LIMIT: usize = 32;

/// One volume on disk, opened on first read and kept open for later ranges.
#[derive(Debug)]
pub(crate) struct FileSource {
    path: PathBuf,
    handle: Mutex<Option<Arc<File>>>,
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
}

static OPEN_FILES: Mutex<VecDeque<Weak<FileSource>>> = Mutex::new(VecDeque::new());

impl FileSource {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            handle: Mutex::new(None),
            #[cfg(test)]
            reads: Default::default(),
        }
    }

    fn handle(self: &Arc<Self>) -> std::io::Result<Arc<File>> {
        let file = {
            let mut handle = self.handle.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(file) = handle.as_ref() {
                return Ok(file.clone());
            }
            let file = Arc::new(File::open(&self.path)?);
            *handle = Some(file.clone());
            file
        };
        // Close the oldest handles outside the pool lock; readers mid-read keep theirs alive.
        let evicted: Vec<_> = {
            let mut open = OPEN_FILES.lock().unwrap_or_else(PoisonError::into_inner);
            open.retain(|source| source.strong_count() > 0);
            open.push_back(Arc::downgrade(self));
            let excess = open.len().saturating_sub(OPEN_FILE_LIMIT);
            open.drain(..excess).collect()
        };
        for source in evicted.iter().filter_map(Weak::upgrade) {
            *source.handle.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
        Ok(file)
    }
}

#[cfg(unix)]
fn read_at(file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, bytes, offset)
}

#[cfg(windows)]
fn read_at(file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, bytes, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(mut file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
    // Without positional reads, a seek and its read must not interleave across threads.
    static SEEK_READ: Mutex<()> = Mutex::new(());
    let _guard = SEEK_READ.lock().unwrap_or_else(PoisonError::into_inner);
    file.seek(SeekFrom::Start(offset))?;
    file.read(bytes)
}

/// Read-ahead per range; the remainder is handed to the next range on the same thread.
const READ_AHEAD: usize = 192 << 10;
/// Reads this large gain nothing from read-ahead but would pay an extra copy.
const DIRECT_READ: usize = 32 << 10;

struct Window {
    start: u64,
    data: Vec<u8>,
}

impl Window {
    fn holds(&self, position: u64) -> bool {
        position
            .checked_sub(self.start)
            .is_some_and(|offset| offset < self.data.len() as u64)
    }
}

thread_local! {
    static PARKED: RefCell<Option<(Weak<FileSource>, Window)>> =
        const { RefCell::new(None) };
}

pub(crate) struct FileCursor<'a> {
    source: &'a Arc<FileSource>,
    position: u64,
    end: u64,
    window: Option<Window>,
}

impl<'a> FileCursor<'a> {
    fn new(source: &'a Arc<FileSource>, range: Range<usize>) -> Self {
        let position = range.start as u64;
        let window = PARKED.with_borrow_mut(|parked| {
            let adopt = parked.as_ref().is_some_and(|(owner, window)| {
                std::ptr::eq(owner.as_ptr(), Arc::as_ptr(source)) && window.holds(position)
            });
            if adopt {
                parked.take().map(|(_, window)| window)
            } else {
                None
            }
        });
        Self {
            source,
            position,
            end: range.end as u64,
            window,
        }
    }

    fn read_disk(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        self.source
            .reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        read_at(&*self.source.handle()?, bytes, self.position)
    }

    fn park(&mut self) {
        if let Some(window) = self.window.take() {
            let owner = Arc::downgrade(self.source);
            let _ = PARKED.try_with(|parked| *parked.borrow_mut() = Some((owner, window)));
        }
    }
}

impl Read for FileCursor<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self
            .window
            .as_ref()
            .is_some_and(|window| window.holds(self.position))
        {
            if bytes.len() >= DIRECT_READ {
                let count = self.read_disk(bytes)?;
                self.position += count as u64;
                return Ok(count);
            }
            let mut data = self
                .window
                .take()
                .map(|window| window.data)
                .unwrap_or_default();
            data.resize(READ_AHEAD, 0);
            let count = self.read_disk(&mut data)?;
            data.truncate(count);
            self.window = Some(Window {
                start: self.position,
                data,
            });
            if count == 0 {
                return Ok(0);
            }
        }
        let window = self.window.as_ref().expect("window was filled above");
        let offset = (self.position - window.start) as usize;
        let count = bytes.len().min(window.data.len() - offset);
        bytes[..count].copy_from_slice(&window.data[offset..offset + count]);
        self.position += count as u64;
        if self.position >= self.end {
            self.park();
        }
        Ok(count)
    }
}

impl Drop for FileCursor<'_> {
    fn drop(&mut self) {
        self.park();
    }
}

/// Range cursors contain only inline state and references to the archive's
/// existing source. Reading a member does not need another heap allocation.
pub(crate) enum RangeReader<'a> {
    Memory(Cursor<&'a [u8]>),
    File(Bounded<FileCursor<'a>>),
    Reader(Bounded<SourceCursor>),
}
impl Read for RangeReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Memory(reader) => reader.read(bytes),
            Self::File(reader) => reader.read(bytes),
            Self::Reader(reader) => reader.read(bytes),
        }
    }
}

/// Like [`std::io::Take`], but a source that ends early is an error, not EOF.
pub(crate) struct Bounded<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Bounded<R> {
    fn new(inner: R, len: usize) -> Self {
        Self {
            inner,
            remaining: len as u64,
        }
    }
}

impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = bytes
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let read = self.inner.read(&mut bytes[..count])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "archive volume ended before its declared length",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<FileSource>),
    Reader(Arc<ReaderSource>),
}

impl ArchiveSource {
    pub(crate) fn file(path: &Path) -> Self {
        Self::File(Arc::new(FileSource::new(path)))
    }

    #[cfg(test)]
    fn is_open(&self) -> bool {
        matches!(self, Self::File(source) if source.handle.lock().unwrap().is_some())
    }

    #[cfg(test)]
    fn disk_reads(&self) -> usize {
        match self {
            Self::File(source) => source.reads.load(std::sync::atomic::Ordering::Relaxed),
            _ => 0,
        }
    }

    pub(crate) fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        match self {
            Self::Memory(data) => data
                .get(range)
                .map(|data| data.to_vec())
                .ok_or(Error::TooShort),
            Self::File(_) => {
                let mut data = vec![0; range.len()];
                self.range_reader(range)?.read_exact(&mut data)?;
                Ok(data)
            }
            Self::Reader(source) => read_exact_at(&mut source.cursor(), range.start, range.len()),
        }
    }

    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                writer.write_all(data)?;
            }
            Self::Reader(_) | Self::File(_) => {
                let mut reader = self.range_reader(range)?;
                std::io::copy(&mut reader, writer)?;
            }
        }
        Ok(())
    }

    pub(crate) fn range_reader(&self, range: Range<usize>) -> Result<RangeReader<'_>> {
        match self {
            Self::Reader(source) => {
                if range.start > range.end || range.end > source.len {
                    return Err(Error::TooShort);
                }
                let mut reader = source.cursor();
                reader.seek(SeekFrom::Start(range.start as u64))?;
                Ok(RangeReader::Reader(Bounded::new(reader, range.len())))
            }
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(RangeReader::Memory(Cursor::new(data)))
            }
            Self::File(source) => {
                if range.start > range.end {
                    return Err(Error::TooShort);
                }
                // Opening here makes a missing volume fail before any member checks.
                source.handle()?;
                let len = range.len();
                Ok(RangeReader::File(Bounded::new(
                    FileCursor::new(source, range),
                    len,
                )))
            }
        }
    }

    pub(crate) fn len(&self) -> Result<usize> {
        match self {
            Self::Reader(source) => Ok(source.len),
            Self::Memory(data) => Ok(data.len()),
            Self::File(source) => usize::try_from(std::fs::metadata(&source.path)?.len())
                .map_err(|_| Error::InvalidHeader("archive size overflows host address size")),
        }
    }

    #[cfg(feature = "recovery")]
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Reader(source) => self.read_range(0..source.len),
            Self::Memory(data) => Ok(data.to_vec()),
            Self::File(_) => self.read_range(0..self.len()?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(name: &str, data: &[u8]) -> (crate::scratch::Scratch, PathBuf) {
        let scratch = crate::scratch::case(name);
        let path = scratch.join("volume.rar");
        std::fs::write(&path, data).unwrap();
        (scratch, path)
    }

    #[cfg(unix)]
    #[test]
    fn file_ranges_keep_reading_after_the_volume_is_unlinked() {
        let (_scratch, path) = volume("source-handle-reuse", b"0123456789");
        let source = ArchiveSource::file(&path);
        assert_eq!(source.read_range(0..2).unwrap(), b"01");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(source.read_range(6..9).unwrap(), b"678");
        let mut copied = Vec::new();
        source.copy_range_to(2..5, &mut copied).unwrap();
        assert_eq!(copied, b"234");
    }

    #[test]
    fn open_volume_handles_stay_bounded_and_evicted_volumes_reopen() {
        let scratch = crate::scratch::case("source-handle-pool");
        let sources: Vec<_> = (0..OPEN_FILE_LIMIT + 8)
            .map(|index| {
                let path = scratch.join(format!("v{index}.rar"));
                std::fs::write(&path, [index as u8; 4]).unwrap();
                ArchiveSource::file(&path)
            })
            .collect();
        for (index, source) in sources.iter().enumerate() {
            assert_eq!(source.read_range(1..2).unwrap(), [index as u8]);
        }
        let open = sources.iter().filter(|source| source.is_open()).count();
        assert!(open <= OPEN_FILE_LIMIT, "{open} handles open");
        assert_eq!(sources[0].read_range(2..3).unwrap(), [0]);
    }

    #[test]
    fn back_to_back_small_ranges_share_one_read_ahead() {
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let (_scratch, path) = volume("source-read-ahead", &data);
        let source = ArchiveSource::file(&path);
        assert_eq!(source.read_range(0..10).unwrap(), data[..10]);
        let mut copied = Vec::new();
        source.copy_range_to(16..300, &mut copied).unwrap();
        assert_eq!(copied, data[16..300]);
        let mut rest = Vec::new();
        source
            .range_reader(300..4096)
            .unwrap()
            .read_to_end(&mut rest)
            .unwrap();
        assert_eq!(rest, data[300..]);
        assert_eq!(source.disk_reads(), 1);
    }

    #[test]
    fn concurrent_ranges_on_one_volume_read_their_own_bytes() {
        let data: Vec<u8> = (0..1 << 20)
            .map(|index: u32| ((index * 7) >> 3) as u8)
            .collect();
        let (_scratch, path) = volume("source-concurrent", &data);
        let source = ArchiveSource::file(&path);
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let (source, data) = (&source, &data);
                scope.spawn(move || {
                    for round in 0..64 {
                        let start = (thread * 131_071 + round * 9_973) % (data.len() - 70_000);
                        let range = start..start + 1 + round * 1_000;
                        assert_eq!(source.read_range(range.clone()).unwrap(), data[range]);
                    }
                });
            }
        });
    }

    #[test]
    fn sibling_cursors_keep_independent_positions_and_range_boundaries() {
        let source = ReaderSource::new(Cursor::new(b"0123456789".to_vec())).unwrap();
        let mut first = source.cursor();
        let mut second = source.cursor();
        second.seek(SeekFrom::End(-3)).unwrap();
        let mut bytes = [0; 2];
        first.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"01");
        second.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"78");
        first.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"23");
        assert!(first.seek(SeekFrom::Current(-5)).is_err());
        assert_eq!(first.stream_position().unwrap(), 4);
        let source = ArchiveSource::Reader(source);
        let mut range = source.range_reader(4..6).unwrap();
        let mut result = Vec::new();
        range.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"45");
        assert!(source.range_reader(9..11).is_err());
        let start = 6;
        let end = 4;
        assert!(source.range_reader(start..end).is_err());
    }

    #[test]
    fn empty_and_exhausted_cursors_do_not_read_the_underlying_source() {
        let source = ReaderSource::new(Cursor::new(b"0123".to_vec())).unwrap();
        assert_eq!(format!("{source:?}"), "ReaderSource { len: 4, .. }");
        let mut cursor = source.cursor();
        assert_eq!(cursor.read(&mut []).unwrap(), 0);
        assert_eq!(cursor.stream_position().unwrap(), 0);
        cursor.seek(SeekFrom::End(0)).unwrap();
        let mut bytes = [0xff; 2];
        assert_eq!(cursor.read(&mut bytes).unwrap(), 0);
        assert_eq!(bytes, [0xff; 2]);
        cursor.seek(SeekFrom::End(10)).unwrap();
        assert_eq!(cursor.read(&mut bytes).unwrap(), 0);
        assert_eq!(cursor.stream_position().unwrap(), 14);
    }

    #[test]
    fn a_panicking_reader_leaves_sibling_cursors_with_a_typed_io_error() {
        struct PanicReader(Cursor<Vec<u8>>);
        impl Seek for PanicReader {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(from)
            }
        }
        impl Read for PanicReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("reader failed during callback");
            }
        }
        let source = ReaderSource::new(PanicReader(Cursor::new(vec![1]))).unwrap();
        let mut first = source.cursor();
        let mut sibling = source.cursor();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            first.read_exact(&mut [0]).unwrap();
        }))
        .is_err());
        let error = sibling.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.to_string(), "archive reader lock poisoned");
        assert!(matches!(Error::from(error), Error::Io(_)));
        assert_eq!(sibling.stream_position().unwrap(), 0);
    }
}
