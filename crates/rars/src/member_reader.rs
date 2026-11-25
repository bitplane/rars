use crate::crc32::Crc32;
use crate::rar13::Rar13Checksum;
use crate::rar50::blake2sp;
use crate::source::{ArchiveSource, RangeReader};
use crate::{Archive, ArchiveMemberRef, ArchiveReadOptions, Error, Result};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;

/// An owned reader over one payload in a single archive.
///
/// Stored, unencrypted members are seekable and verify their checksum when
/// read sequentially from the start to the end. Any seek disables that
/// verification, including a query of the current position. A checksum mismatch
/// is returned by the read that reaches the end.
///
/// Compressed or encrypted members stream on native targets. Only seeks to
/// the current position succeed. Decode errors come from [`Read::read`] after
/// any available prefix and wrap the archive error. Drop the reader to cancel
/// and join its producer. Cancellation is cooperative, as described by
/// [`crate::ReadCancellation`]. Bare WebAssembly decodes these members in memory
/// during [`Archive::open_member`] and serves them from a seekable cursor.
///
/// Use drop for cancellation and read results for errors instead of supplying
/// a cancellation token or member error handler in [`ArchiveReadOptions`].
pub struct MemberReader {
    inner: MemberReaderInner,
}

enum MemberReaderInner {
    Stored(StoredReader),
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Streaming(native::Stream),
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    Buffered(io::Cursor<Vec<u8>>),
}

impl MemberReader {
    /// Whether the reader supports seeks beyond its current position.
    pub fn is_seekable(&self) -> bool {
        match self.inner {
            MemberReaderInner::Stored(_) => true,
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            MemberReaderInner::Streaming(_) => false,
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            MemberReaderInner::Buffered(_) => true,
        }
    }
}

impl Read for MemberReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            MemberReaderInner::Stored(reader) => reader.read(buf),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            MemberReaderInner::Streaming(reader) => reader.read(buf),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            MemberReaderInner::Buffered(reader) => reader.read(buf),
        }
    }
}

impl Seek for MemberReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            MemberReaderInner::Stored(reader) => reader.seek(from),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            MemberReaderInner::Streaming(reader) => reader.seek(from),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            MemberReaderInner::Buffered(reader) => reader.seek(from),
        }
    }
}

type MemberItem = Result<(usize, Vec<u8>)>;

/// An owned iterator of selected payloads in archive order in a single archive.
///
/// Each selected index is yielded once. Independent member failures are
/// yielded as errors and traversal continues. A fatal error ends iteration
/// after its error item. Each successful item is a fully decoded buffer.
///
/// On native targets drop the iterator to cancel and join its producer. On
/// bare WebAssembly the selection is decoded into memory at construction and
/// any extraction failure becomes the sole item. Supply neither a cancellation
/// token nor a member error handler in [`ArchiveReadOptions`].
pub struct MembersIter {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    inner: Option<native::Producer<MemberItem>>,
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    inner: std::vec::IntoIter<MemberItem>,
}

impl Iterator for MembersIter {
    type Item = MemberItem;

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            match self.inner.as_mut()?.receive() {
                Ok(item) => item,
                Err(error) => Some(Err(error)),
            }
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        self.inner.next()
    }
}

pub(crate) fn open_member(
    archive: &Archive,
    index: usize,
    options: ArchiveReadOptions<'_>,
) -> Result<MemberReader> {
    validate_options(options)?;
    let member = archive
        .member_refs()
        .nth(index)
        .ok_or(Error::InvalidArgument("member index is out of range"))?;
    if member.is_directory() || member.is_redirection() {
        return Err(Error::InvalidArgument("member has no file payload"));
    }
    let metadata = member.to_owned().meta;
    if metadata.is_split_before || metadata.is_split_after {
        return Err(Error::InvalidArgument("split member requires a volume set"));
    }
    let inner = if metadata.is_stored && !metadata.is_encrypted {
        crate::output_limit::OutputBudget::new(options)
            .check(metadata.unpacked_size, &metadata.name)?;
        MemberReaderInner::Stored(StoredReader::open(archive, member, metadata)?)
    } else {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            MemberReaderInner::Streaming(native::open_stream(
                archive,
                index,
                metadata.unpacked_size,
                options,
            )?)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let data = archive
                .read_member_at_with_options(index, options)?
                .ok_or(Error::InvalidArgument("member has no file payload"))?;
            MemberReaderInner::Buffered(io::Cursor::new(data))
        }
    };
    Ok(MemberReader { inner })
}

pub(crate) fn read_members_iter(
    archive: &Archive,
    indices: &[usize],
    options: ArchiveReadOptions<'_>,
) -> Result<MembersIter> {
    validate_options(options)?;
    let mut indices = indices.to_vec();
    indices.sort_unstable();
    indices.dedup();
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    let inner = native::members(archive, indices, options)?;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let inner = match archive.read_members_at_with_options(&indices, options) {
        Ok(buffers) => indices
            .into_iter()
            .zip(buffers)
            .filter_map(|(index, bytes)| bytes.map(|bytes| Ok((index, bytes))))
            .collect::<Vec<_>>(),
        Err(error) => vec![Err(error)],
    }
    .into_iter();
    Ok(MembersIter { inner })
}

fn validate_options(options: ArchiveReadOptions<'_>) -> Result<()> {
    if options.cancellation.is_some() || options.member_errors.is_some() {
        return Err(Error::InvalidArgument(
            "drop the reader or iterator to cancel. Extraction errors come back from read or next",
        ));
    }
    Ok(())
}

enum Checksum {
    Legacy(Rar13Checksum, u16),
    Crc32(Crc32, u32),
    Blake2sp(Box<blake2sp::Hasher>, [u8; 32]),
}

impl Checksum {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Legacy(checksum, _) => checksum.update(bytes),
            Self::Crc32(checksum, _) => checksum.update(bytes),
            Self::Blake2sp(checksum, _) => checksum.update(bytes),
        }
    }

    fn verify(self) -> Result<()> {
        match self {
            Self::Legacy(checksum, expected) => {
                let actual = checksum.finish();
                if expected != actual {
                    return Err(Error::CrcMismatch { expected, actual });
                }
            }
            Self::Crc32(checksum, expected) => {
                let actual = checksum.finish();
                if expected != actual {
                    return Err(Error::Crc32Mismatch { expected, actual });
                }
            }
            Self::Blake2sp(checksum, expected) => {
                if checksum.finalize() != expected {
                    return Err(Error::HashMismatch { hash_type: 0 });
                }
            }
        }
        Ok(())
    }
}

struct StoredReader {
    source: ArchiveSource,
    range: Range<usize>,
    reader: Option<RangeReader<'static>>,
    position: u64,
    name: Vec<u8>,
    checksum: Option<Checksum>,
    end_error: Option<Error>,
}

impl StoredReader {
    fn open(
        archive: &Archive,
        member: ArchiveMemberRef<'_>,
        metadata: crate::ArchiveMemberMeta,
    ) -> Result<Self> {
        let (source, range, checksum, cut_short, history_lost) = match (archive, member) {
            (Archive::Rar13(archive), ArchiveMemberRef::Rar13(entry)) => (
                &archive.source,
                entry.packed_range.clone(),
                Some(Checksum::Legacy(
                    Rar13Checksum::new(),
                    entry.header.file_crc,
                )),
                entry.cut_short,
                false,
            ),
            (Archive::Rar15To40(archive), ArchiveMemberRef::Rar15To40(file)) => (
                &archive.source,
                file.packed_range.clone(),
                Some(Checksum::Crc32(Crc32::new(), file.file_crc)),
                file.is_cut_short(),
                file.history_lost,
            ),
            (Archive::Rar50Plus(archive), ArchiveMemberRef::Rar50Plus(file)) => {
                let checksum = match file.hash.as_ref().filter(|hash| hash.hash_type == 0) {
                    Some(hash) => {
                        let expected = hash.data.as_slice().try_into().map_err(|_| {
                            Error::InvalidHeader("RAR 5 BLAKE2sp hash record has invalid length")
                        })?;
                        Some(Checksum::Blake2sp(
                            Box::new(blake2sp::Hasher::new()),
                            expected,
                        ))
                    }
                    None => file
                        .data_crc32
                        .map(|crc| Checksum::Crc32(Crc32::new(), crc)),
                };
                (
                    &archive.source,
                    file.block.data_range.clone(),
                    checksum,
                    file.is_cut_short(),
                    file.history_lost,
                )
            }
            _ => unreachable!("member belongs to the matching archive family"),
        };
        let end_error = if cut_short {
            Some(Error::MemberCutShort {
                packed: metadata.packed_size,
                present: range.len() as u64,
            })
        } else if range.len() as u64 != metadata.unpacked_size
            || metadata.packed_size != metadata.unpacked_size
        {
            return Err(Error::InvalidHeader(
                "stored member has mismatched packed and unpacked sizes",
            )
            .at_entry(metadata.name, "opening"));
        } else if history_lost {
            Some(Error::SolidHistoryLost)
        } else {
            None
        };
        let reader = source.owned_range_reader(range.clone())?;
        Ok(Self {
            source: source.clone(),
            range,
            reader: Some(reader),
            position: 0,
            name: metadata.name,
            checksum,
            end_error,
        })
    }

    fn reached_end(&mut self) -> io::Result<()> {
        let result = match self.end_error.take() {
            Some(error) => {
                self.checksum = None;
                Err(error)
            }
            None => self.checksum.take().map_or(Ok(()), Checksum::verify),
        };
        result.map_err(|error| io::Error::other(error.at_entry(self.name.clone(), "verifying")))
    }
}

impl Read for StoredReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = self.range.len() as u64;
        if self.position >= len {
            if self.position == len {
                self.reached_end()?;
            }
            return Ok(0);
        }
        if self.reader.is_none() {
            let start = self.range.start + self.position as usize;
            self.reader = Some(
                self.source
                    .owned_range_reader(start..self.range.end)
                    .map_err(io::Error::other)?,
            );
        }
        let count = self.reader.as_mut().expect("range is open").read(buf)?;
        self.position += count as u64;
        if let Some(checksum) = &mut self.checksum {
            checksum.update(&buf[..count]);
        }
        if self.position == len {
            self.reached_end()?;
        }
        Ok(count)
    }
}

fn seek_position(from: SeekFrom, position: u64, len: u64) -> Option<u64> {
    match from {
        SeekFrom::Start(position) => Some(position),
        SeekFrom::Current(offset) => position.checked_add_signed(offset),
        SeekFrom::End(offset) => len.checked_add_signed(offset),
    }
}

impl Seek for StoredReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.checksum = None;
        let position = seek_position(from, self.position, self.range.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek position"))?;
        if position != self.position {
            self.reader = None;
            self.position = position;
        }
        Ok(position)
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native {
    use super::{seek_position, Archive, ArchiveReadOptions, MemberItem, Result};
    use crate::member_read::predecessor_decision;
    use crate::{ExtractionDecision, ExtractionErrorAction, Rar50Scratch, ReadCancellation};
    use std::cell::RefCell;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
    use std::rc::Rc;
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    const CHUNK_SIZE: usize = 64 * 1024;
    const CHUNK_CAPACITY: usize = 16;

    struct OwnedOptions {
        options: ArchiveReadOptions<'static>,
        password: Option<Vec<u8>>,
        scratch: Option<Rar50Scratch>,
    }

    impl OwnedOptions {
        fn new(options: ArchiveReadOptions<'_>) -> Self {
            Self {
                options: ArchiveReadOptions {
                    password: None,
                    cancellation: None,
                    rar50_scratch: None,
                    member_errors: None,
                    ..options
                },
                password: options.password.map(<[u8]>::to_vec),
                scratch: options.rar50_scratch.cloned(),
            }
        }

        fn borrow<'a>(&'a self, cancellation: &'a ReadCancellation) -> ArchiveReadOptions<'a> {
            ArchiveReadOptions {
                password: self.password.as_deref(),
                rar50_scratch: self.scratch.as_ref(),
                cancellation: Some(cancellation),
                ..self.options
            }
        }
    }

    enum Message<T> {
        Item(T),
        End(Result<()>),
    }

    pub(super) struct Producer<T> {
        receiver: Option<Receiver<Message<T>>>,
        cancellation: Arc<ReadCancellation>,
        thread: Option<JoinHandle<()>>,
    }

    impl<T: Send + 'static> Producer<T> {
        fn spawn(
            name: &str,
            capacity: usize,
            options: ArchiveReadOptions<'_>,
            work: impl FnOnce(&SyncSender<Message<T>>, ArchiveReadOptions<'_>) -> Result<()>
                + Send
                + 'static,
        ) -> Result<Self> {
            let (sender, receiver) = mpsc::sync_channel(capacity);
            let cancellation = Arc::new(ReadCancellation::new());
            let token = Arc::clone(&cancellation);
            let options = OwnedOptions::new(options);
            let thread = thread::Builder::new().name(name.into()).spawn(move || {
                let result = work(&sender, options.borrow(&token));
                let _ = sender.send(Message::End(result));
            })?;
            Ok(Self {
                receiver: Some(receiver),
                cancellation,
                thread: Some(thread),
            })
        }

        pub(super) fn receive(&mut self) -> Result<Option<T>> {
            let Some(receiver) = &self.receiver else {
                return Ok(None);
            };
            match receiver.recv() {
                Ok(Message::Item(item)) => Ok(Some(item)),
                terminal => {
                    self.receiver = None;
                    match terminal {
                        Ok(Message::End(result)) => result.map(|()| None),
                        _ => Err(io::Error::other("archive member producer disconnected").into()),
                    }
                }
            }
        }
    }

    impl<T> Drop for Producer<T> {
        fn drop(&mut self) {
            self.cancellation.cancel();
            // A producer waiting for channel space must wake before we join it.
            self.receiver = None;
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn send<T>(sender: &SyncSender<Message<T>>, item: T) -> io::Result<()> {
        sender.send(Message::Item(item)).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "archive member consumer dropped")
        })
    }

    struct ChunkWriter {
        sender: SyncSender<Message<Vec<u8>>>,
        pending: Vec<u8>,
    }

    impl ChunkWriter {
        fn flush(&mut self) -> io::Result<()> {
            if !self.pending.is_empty() {
                send(&self.sender, std::mem::take(&mut self.pending))?;
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedChunkWriter(Rc<RefCell<ChunkWriter>>);

    impl Write for SharedChunkWriter {
        fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
            let length = bytes.len();
            let mut writer = self.0.borrow_mut();
            while !bytes.is_empty() {
                let count = bytes.len().min(CHUNK_SIZE - writer.pending.len());
                writer.pending.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if writer.pending.len() == CHUNK_SIZE {
                    writer.flush()?;
                }
            }
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.borrow_mut().flush()
        }
    }

    pub(super) struct Stream {
        producer: Producer<Vec<u8>>,
        chunk: Cursor<Vec<u8>>,
        position: u64,
        len: u64,
    }

    pub(super) fn open_stream(
        archive: &Archive,
        target: usize,
        len: u64,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Stream> {
        let archive = archive.clone();
        let producer = Producer::spawn(
            "rars-member-reader",
            CHUNK_CAPACITY,
            options,
            move |sender, options| {
                let solid = archive.is_solid();
                let mut writer = SharedChunkWriter(Rc::new(RefCell::new(ChunkWriter {
                    sender: sender.clone(),
                    pending: Vec::new(),
                })));
                let mut current = 0;
                let result = archive.extract_with_control(options, |member| {
                    let index = current;
                    current += 1;
                    Ok(if index > target {
                        ExtractionDecision::Stop
                    } else if index == target {
                        ExtractionDecision::Extract(Box::new(writer.clone()))
                    } else {
                        predecessor_decision(
                            solid && !member.meta.is_directory && !member.meta.is_redirection,
                        )
                    })
                });
                // Extractors flush a verified member. A failed member can
                // still have an unwritten final chunk of output.
                let flushed = writer.flush();
                result?;
                flushed?;
                Ok(())
            },
        )?;
        Ok(Stream {
            producer,
            chunk: Cursor::new(Vec::new()),
            position: 0,
            len,
        })
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.chunk.position() == self.chunk.get_ref().len() as u64 {
                match self.producer.receive().map_err(io::Error::other)? {
                    Some(bytes) => self.chunk = Cursor::new(bytes),
                    None => {
                        self.len = self.position;
                        return Ok(0);
                    }
                }
            }
            let count = self.chunk.read(buf)?;
            self.position += count as u64;
            Ok(count)
        }
    }

    impl Seek for Stream {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            if seek_position(from, self.position, self.len) == Some(self.position) {
                Ok(self.position)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "streamed archive members can only seek to their current position",
                ))
            }
        }
    }

    struct MemberWriter {
        sender: SyncSender<Message<MemberItem>>,
        index: usize,
        bytes: Vec<u8>,
    }

    impl Write for MemberWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            send(
                &self.sender,
                Ok((self.index, std::mem::take(&mut self.bytes))),
            )
        }
    }

    pub(super) fn members(
        archive: &Archive,
        mut indices: Vec<usize>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Option<Producer<MemberItem>>> {
        let mut requested = indices.iter().copied().peekable();
        let payloads = archive
            .member_refs()
            .enumerate()
            .filter_map(|(index, member)| {
                if requested.next_if_eq(&index).is_some()
                    && !member.is_directory()
                    && !member.is_redirection()
                {
                    Some(index)
                } else {
                    None
                }
            });
        let Some(last) = payloads.last() else {
            return Ok(None);
        };
        indices.truncate(indices.partition_point(|index| *index <= last));
        let archive = archive.clone();
        Producer::spawn(
            "rars-members-iterator",
            1,
            options,
            move |sender, options| {
                let solid = archive.is_solid();
                let mut requested = indices.into_iter().peekable();
                let mut current = 0;
                archive.extract_with_control_and_errors(
                    options,
                    |member| {
                        let index = current;
                        current += 1;
                        let selected = requested.next_if_eq(&index).is_some();
                        Ok(if index > last {
                            ExtractionDecision::Stop
                        } else if member.meta.is_directory || member.meta.is_redirection {
                            ExtractionDecision::Skip
                        } else if selected {
                            ExtractionDecision::Extract(Box::new(MemberWriter {
                                sender: sender.clone(),
                                index,
                                bytes: Vec::new(),
                            }))
                        } else {
                            predecessor_decision(solid)
                        })
                    },
                    |_, error| {
                        send(sender, Err(error.clone()))?;
                        Ok(ExtractionErrorAction::Continue)
                    },
                )?;
                Ok(())
            },
        )
        .map(Some)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::mpsc::TrySendError;
        use std::time::Duration;

        #[test]
        fn full_chunk_channel_disconnects_before_joining() {
            let (full, observe_full) = mpsc::channel();
            let (done, observe_drop) = mpsc::channel();
            let (done_with_write, observe_write) = mpsc::channel();
            let producer = Producer::spawn(
                "rars-member-reader",
                CHUNK_CAPACITY,
                ArchiveReadOptions::new(),
                move |sender, options| {
                    let mut writer = SharedChunkWriter(Rc::new(RefCell::new(ChunkWriter {
                        sender: sender.clone(),
                        pending: Vec::new(),
                    })));
                    let chunk = vec![0; CHUNK_SIZE];
                    for _ in 0..CHUNK_CAPACITY {
                        writer.write_all(&chunk)?;
                    }
                    assert!(matches!(
                        sender.try_send(Message::Item(Vec::new())),
                        Err(TrySendError::Full(_))
                    ));
                    full.send(()).unwrap();
                    assert_eq!(
                        writer.write_all(&chunk).unwrap_err().kind(),
                        io::ErrorKind::BrokenPipe
                    );
                    assert!(options.cancellation.unwrap().is_cancelled());
                    done_with_write.send(()).unwrap();
                    Ok(())
                },
            )
            .unwrap();
            observe_full.recv_timeout(Duration::from_secs(10)).unwrap();
            thread::scope(|scope| {
                scope.spawn(move || {
                    drop(producer);
                    done.send(()).unwrap();
                });
                observe_drop.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            observe_write.try_recv().unwrap();
        }
    }
}
