//! Reading and writing archive members one at a time.
//!
//! The RAR 1.3 to 4.x codecs compress a member as a unit, so those writers
//! cannot avoid having a member resident. What they can avoid is having *every*
//! member resident, which is what they used to do: the caller read all the
//! inputs, the writer built the whole archive in a `Vec`, and peak memory was a
//! multiple of the total input rather than of the largest member.

use crate::error::{Error, Result};
use crate::streaming::EntrySource;
use std::borrow::Cow;
use std::io::{Read, Seek, Write};

pub(crate) use crate::entropy::fill_entropy;

/// Attribute a writer failure without blaming a member for cancellation.
pub(crate) fn member_error(error: Error, name: &[u8], operation: &'static str) -> Error {
    if error.kind() == crate::ErrorKind::Cancelled || error.entry_context().is_some() {
        error
    } else {
        error.at_entry(name.to_vec(), operation)
    }
}

/// How much of a member is read at a time when it is walked rather than held.
const WALK_CHUNK: usize = 256 * 1024;

/// Where one member's bytes come from.
///
/// A caller who already holds the whole input hands over a slice; one writing
/// from disk hands over a source that is opened when the member is coded and
/// closed again straight after. Everything downstream is the same either way.
pub(crate) enum MemberBytes<'a> {
    Borrowed(&'a [u8]),
    Source(&'a EntrySource),
    /// Builder inputs retain their source-read context even when loading is
    /// deferred into a writer's preparation phase.
    NamedSource(&'a EntrySource, &'a [u8]),
}

impl<'a> MemberBytes<'a> {
    pub(crate) fn len(&self) -> Result<u64> {
        let result = match self {
            Self::Borrowed(data) => Ok(data.len() as u64),
            Self::Source(source) | Self::NamedSource(source, _) => source.len(),
        };
        result.map_err(|error| self.source_error(error))
    }

    fn source_error(&self, error: Error) -> Error {
        match self {
            Self::NamedSource(_, name) => member_error(error, name, "reading source"),
            _ => error,
        }
    }

    /// The whole member, borrowed when the caller already had it.
    #[cfg(test)]
    pub(crate) fn load(&self) -> Result<Cow<'_, [u8]>> {
        self.load_exact_with_progress(self.len()?, None)
    }

    /// Use the source size already captured for the header and workspace.
    /// Requerying a changing path here could disagree with that header. Inline
    /// bytes remain borrowed and immutable throughout the write.
    pub(crate) fn load_exact_with_progress(
        &self,
        expected: u64,
        progress: Option<crate::write_progress::ProgressReporter<'_>>,
    ) -> Result<Cow<'_, [u8]>> {
        self.load_exact(expected, progress)
            .map_err(|error| self.source_error(error))
    }

    fn load_exact(
        &self,
        expected: u64,
        progress: Option<crate::write_progress::ProgressReporter<'_>>,
    ) -> Result<Cow<'_, [u8]>> {
        crate::write_progress::check_cancelled(progress)?;
        match self {
            Self::Borrowed(data) => Ok(Cow::Borrowed(data)),
            Self::Source(source) | Self::NamedSource(source, _) => {
                let capacity = usize::try_from(expected).map_err(|_| {
                    Error::InvalidArgument("member is larger than this host can hold")
                })?;
                let mut data = Vec::with_capacity(capacity);
                crate::write_progress::check_cancelled(progress)?;
                let mut reader = crate::write_progress::CancellableIo {
                    inner: source.open()?,
                    progress,
                };
                reader.by_ref().take(expected).read_to_end(&mut data)?;
                crate::write_progress::check_cancelled(progress)?;
                check_source_length(
                    &mut reader,
                    data.len() as u64,
                    expected,
                    "entry source size changed while compressing",
                )?;
                crate::write_progress::check_cancelled(progress)?;
                Ok(Cow::Owned(data))
            }
        }
    }

    /// Walks the member in chunks without holding it, which is how a stored
    /// one is checksummed on its way through.
    #[cfg(test)]
    pub(crate) fn walk(&self, visit: impl FnMut(&[u8])) -> Result<()> {
        self.walk_with_progress(None, visit)
    }

    #[cfg(test)]
    fn walk_with_progress(
        &self,
        progress: Option<crate::write_progress::ProgressReporter<'_>>,
        visit: impl FnMut(&[u8]),
    ) -> Result<()> {
        crate::write_progress::check_cancelled(progress)?;
        self.walk_exact_with_progress(self.len()?, progress, visit)
    }

    /// Walk against the same captured source size that the member header uses.
    pub(crate) fn walk_exact_with_progress(
        &self,
        expected: u64,
        progress: Option<crate::write_progress::ProgressReporter<'_>>,
        visit: impl FnMut(&[u8]),
    ) -> Result<()> {
        self.walk_exact(expected, progress, visit)
            .map_err(|error| self.source_error(error))
    }

    fn walk_exact(
        &self,
        expected: u64,
        progress: Option<crate::write_progress::ProgressReporter<'_>>,
        mut visit: impl FnMut(&[u8]),
    ) -> Result<()> {
        crate::write_progress::check_cancelled(progress)?;
        match self {
            Self::Borrowed(data) => {
                for chunk in data.chunks(WALK_CHUNK) {
                    crate::write_progress::check_cancelled(progress)?;
                    visit(chunk);
                }
            }
            Self::Source(source) | Self::NamedSource(source, _) => {
                crate::write_progress::check_cancelled(progress)?;
                let mut reader = crate::write_progress::CancellableIo {
                    inner: source.open()?,
                    progress,
                };
                let mut limited = reader.by_ref().take(expected);
                let mut observed = 0;
                let mut buffer = vec![0u8; WALK_CHUNK];
                loop {
                    let read = limited.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    observed += read as u64;
                    visit(&buffer[..read]);
                }
                crate::write_progress::check_cancelled(progress)?;
                check_source_length(
                    &mut reader,
                    observed,
                    expected,
                    "entry source size changed while reading",
                )?;
            }
        }
        crate::write_progress::check_cancelled(progress)?;
        Ok(())
    }

    /// A reader over the member, for callers that walk it more than once.
    pub(crate) fn open(&self) -> Result<Box<dyn crate::streaming::EntryReader + 'a>> {
        match self {
            Self::Borrowed(data) => Ok(Box::new(std::io::Cursor::new(*data))),
            Self::Source(source) | Self::NamedSource(source, _) => {
                source.open().map_err(|error| self.source_error(error))
            }
        }
    }

    /// The member as a stored payload, which is never loaded: written from
    /// the caller's bytes, or copied from its source.
    pub(crate) fn stored(&self) -> MemberPayload<'a> {
        match self {
            Self::Borrowed(data) => MemberPayload::Borrowed(data),
            Self::Source(source) | Self::NamedSource(source, _) => MemberPayload::Copied(source),
        }
    }

    /// The source behind this member, when there is one to copy from.
    pub(crate) fn source(&self) -> Option<&'a EntrySource> {
        match self {
            Self::Borrowed(_) => None,
            Self::Source(source) | Self::NamedSource(source, _) => Some(source),
        }
    }

    /// The member has been written and verified, so this write will not
    /// reopen its session-owned staged payload. Public source factories keep
    /// their usual reopenable behavior.
    pub(crate) fn release(&self) {
        if let Some(source) = self.source() {
            source.release();
        }
    }
}

pub(crate) trait SeekWrite: Write + Seek {}

impl<T: Write + Seek + ?Sized> SeekWrite for T {}

/// Seeking lets a writer patch a header once the bytes behind it are known.
pub(crate) enum Output<W, S> {
    Stream(W),
    Seekable(S),
}

/// One shape for every family, so the seekable path is not re-derived per format.
pub(crate) struct ArchiveOutput<W, S> {
    pub(crate) to: Output<W, S>,
    /// Opt-in, so a family that cannot yet stream a member keeps holding each one.
    pub(crate) stream_above: Option<u64>,
}

pub(crate) type CallerOutput<'a> = ArchiveOutput<&'a mut dyn Write, &'a mut dyn SeekWrite>;

/// Every write checks cancellation, so a large copy stops promptly.
pub(crate) type CancellableOutput<'o, 'p> = ArchiveOutput<
    crate::write_progress::CancellableIo<'p, &'o mut dyn Write>,
    crate::write_progress::CancellableIo<'p, &'o mut dyn SeekWrite>,
>;

impl<'a> CallerOutput<'a> {
    pub(crate) fn stream(output: &'a mut dyn Write) -> Self {
        Self {
            to: Output::Stream(output),
            stream_above: None,
        }
    }

    pub(crate) fn seekable(output: &'a mut dyn SeekWrite) -> Self {
        Self {
            to: Output::Seekable(output),
            stream_above: None,
        }
    }

    pub(crate) fn streaming_above(self, limit: u64) -> Self {
        Self {
            stream_above: Some(limit),
            ..self
        }
    }

    pub(crate) fn cancellable<'p>(
        self,
        progress: Option<crate::write_progress::ProgressReporter<'p>>,
    ) -> CancellableOutput<'a, 'p> {
        use crate::write_progress::CancellableIo;
        ArchiveOutput {
            to: match self.to {
                Output::Stream(inner) => Output::Stream(CancellableIo { inner, progress }),
                Output::Seekable(inner) => Output::Seekable(CancellableIo { inner, progress }),
            },
            stream_above: self.stream_above,
        }
    }
}

impl<W: Write, S: Write + Seek> ArchiveOutput<W, S> {
    pub(crate) fn writer(&mut self) -> &mut dyn Write {
        match &mut self.to {
            Output::Stream(output) => output,
            Output::Seekable(output) => output,
        }
    }

    pub(crate) fn as_seekable(&mut self) -> Option<&mut S> {
        match &mut self.to {
            Output::Stream(_) => None,
            Output::Seekable(output) => Some(output),
        }
    }

    pub(crate) fn can_seek(&self) -> bool {
        matches!(self.to, Output::Seekable(_))
    }
}

/// A rewrite of another length would overwrite the payload, so it is refused unwritten.
pub(crate) fn patch_header(
    output: &mut (impl Write + Seek + ?Sized),
    at: u64,
    len: u64,
    header: &[u8],
    changed: Error,
) -> Result<()> {
    if header.len() as u64 != len {
        return Err(changed);
    }
    let end = output.stream_position()?;
    output.seek(std::io::SeekFrom::Start(at))?;
    output.write_all(header)?;
    output.seek(std::io::SeekFrom::Start(end))?;
    Ok(())
}

/// Legacy writers don't charge codec and source allocations, so cannot honour a quota.
pub(crate) fn refuse_managed_memory(
    resources: &crate::WriterResources,
    family: crate::ArchiveFamily,
) -> Result<()> {
    if resources.max_preparation_bytes().is_none() && resources.max_memory_bytes().is_none() {
        return Ok(());
    }
    Err(Error::UnsupportedFamilyFeature {
        family,
        feature: if resources.max_memory_bytes().is_some() {
            "aggregate managed-memory limit"
        } else {
            "preparation memory quota"
        },
    })
}

/// A member's bytes as they will appear in the archive.
pub(crate) enum MemberPayload<'a> {
    /// Already in memory: everything compressed, and anything encrypted.
    Packed(Vec<u8>),
    /// Copied from the source as the archive is written, which keeps a stored
    /// member off the heap however large it is.
    Copied(&'a EntrySource),
    /// A stored member written from the bytes the caller handed over, which
    /// would otherwise be copied only to be written out.
    Borrowed(&'a [u8]),
}

impl MemberPayload<'_> {
    /// How many bytes this payload puts in the archive. A copied member is
    /// stored verbatim, so its packed size is the size it came in at.
    pub(crate) fn size(&self, unpacked_size: u64) -> u64 {
        match self {
            Self::Packed(packed) => packed.len() as u64,
            Self::Borrowed(data) => data.len() as u64,
            Self::Copied(_) => unpacked_size,
        }
    }

    pub(crate) fn write_to(&self, output: &mut dyn Write, expected: u64) -> Result<()> {
        match self {
            Self::Packed(packed) => output.write_all(packed)?,
            Self::Borrowed(data) => output.write_all(data)?,
            Self::Copied(source) => {
                let mut reader = source.open()?;
                let copied = std::io::copy(&mut reader.by_ref().take(expected), output)?;
                check_source_length(
                    &mut *reader,
                    copied,
                    expected,
                    "entry source size changed while writing",
                )?;
            }
        }
        Ok(())
    }
}

// Consume at most the advertised length plus one probe byte, including for a
// source that keeps growing. The extra byte is never passed to a codec or sink.
pub(crate) fn check_source_length(
    reader: &mut dyn Read,
    observed: u64,
    expected: u64,
    message: &'static str,
) -> Result<()> {
    if observed != expected {
        return Err(Error::SourceChanged(message));
    }
    let mut probe = [0];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Error::SourceChanged(message)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
pub(crate) fn fingerprint<'a>(outputs: impl IntoIterator<Item = &'a [u8]>) -> String {
    outputs
        .into_iter()
        .map(|bytes| format!("{}:{:08x}", bytes.len(), crate::crc32::crc32(bytes)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
pub(crate) fn assert_fingerprints(actual: &[(String, String)], expected: &[(&str, &str)]) {
    for (name, fingerprint) in actual {
        let want = expected
            .iter()
            .find(|(case, _)| case == name)
            .map(|(_, want)| *want);
        assert_eq!(Some(fingerprint.as_str()), want, "{name}: {actual:?}");
    }
}

#[cfg(test)]
pub(crate) fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Tells a member read as its payload is written from one read whole first.
#[cfg(all(test, feature = "encryption"))]
pub(crate) struct Watch {
    written: std::sync::Arc<crate::atomic64::AtomicU64>,
    opens: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
}

#[cfg(all(test, feature = "encryption"))]
impl Watch {
    /// The archive output, counted so the source can see how far it has got.
    pub(crate) fn sink<'a>(&self, inner: &'a mut Vec<u8>) -> impl Write + 'a {
        struct Sink<'a> {
            inner: &'a mut Vec<u8>,
            written: std::sync::Arc<crate::atomic64::AtomicU64>,
        }
        impl Write for Sink<'_> {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.inner.extend_from_slice(buffer);
                self.written
                    .fetch_add(buffer.len() as u64, std::sync::atomic::Ordering::Relaxed);
                Ok(buffer.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        Sink {
            inner,
            written: std::sync::Arc::clone(&self.written),
        }
    }

    /// How much archive was written between the first and last reads of the
    /// source's last opening. Nothing, if the member was loaded before writing.
    pub(crate) fn written_while_reading(&self) -> u64 {
        let opens = self.opens.lock().unwrap();
        opens.last().map_or(0, |&(first, last)| last - first)
    }
}

/// A source over `data` whose reads note how much archive has been written.
#[cfg(all(test, feature = "encryption"))]
pub(crate) fn watched_source(data: Vec<u8>) -> (EntrySource, Watch) {
    use crate::atomic64::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    struct Watched {
        inner: std::io::Cursor<Arc<[u8]>>,
        written: Arc<AtomicU64>,
        opens: Arc<Mutex<Vec<(u64, u64)>>>,
    }
    impl Read for Watched {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let written = self.written.load(Ordering::Relaxed);
            self.opens.lock().unwrap().last_mut().unwrap().1 = written;
            self.inner.read(buffer)
        }
    }
    impl std::io::Seek for Watched {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(from)
        }
    }

    let watch = Watch {
        written: Arc::new(AtomicU64::new(0)),
        opens: Arc::new(Mutex::new(Vec::new())),
    };
    let len = data.len() as u64;
    let data: Arc<[u8]> = data.into();
    let written = Arc::clone(&watch.written);
    let opens = Arc::clone(&watch.opens);
    let source = EntrySource::from_opener(len, move || {
        let now = written.load(Ordering::Relaxed);
        opens.lock().unwrap().push((now, now));
        Ok(Box::new(Watched {
            inner: std::io::Cursor::new(Arc::clone(&data)),
            written: Arc::clone(&written),
            opens: Arc::clone(&opens),
        }))
    });
    (source, watch)
}

#[cfg(test)]
mod tests {
    #[test]
    fn captured_source_size_controls_loading_and_checksum_walks() {
        struct Source;
        impl crate::streaming::SourceFactory for Source {
            fn len(&self) -> Result<u64> {
                panic!("must use the size already captured for the member header")
            }
            fn open(&self) -> Result<Box<dyn crate::streaming::EntryReader>> {
                Ok(Box::new(std::io::Cursor::new(b"abc".as_slice())))
            }
        }
        for expected in [0, 1, 3, 4] {
            let source = EntrySource::from_factory(Source);
            let member = MemberBytes::Source(&source);
            let loaded = member.load_exact_with_progress(expected, None);
            let mut observed = Vec::new();
            let walked = member.walk_exact_with_progress(expected, None, |chunk| {
                observed.extend_from_slice(chunk)
            });
            if expected == 3 {
                assert_eq!(loaded.unwrap().as_ref(), b"abc");
                walked.unwrap();
                assert_eq!(observed, b"abc");
            } else {
                assert_eq!(loaded.unwrap_err().kind(), crate::ErrorKind::SourceChanged);
                assert_eq!(walked.unwrap_err().kind(), crate::ErrorKind::SourceChanged);
            }
        }
    }

    #[test]
    fn source_end_probe_retries_interruptions_and_reports_other_io_errors() {
        struct Probe {
            calls: usize,
            fail: bool,
        }
        impl std::io::Read for Probe {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.calls == 1 {
                    Err(std::io::ErrorKind::Interrupted.into())
                } else if self.fail {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(0)
                }
            }
        }
        let mut end = Probe {
            calls: 0,
            fail: false,
        };
        super::check_source_length(&mut end, 7, 7, "changed").unwrap();
        assert_eq!(end.calls, 2);
        let mut failed = Probe {
            calls: 0,
            fail: true,
        };
        assert_eq!(
            super::check_source_length(&mut failed, 7, 7, "changed")
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Io
        );
    }

    #[test]
    fn a_patched_header_is_rewritten_in_place_and_the_cursor_returns_to_the_end() {
        let mut output = std::io::Cursor::new(b"head----tail".to_vec());
        output.set_position(12);
        let changed = Error::WriterFailure("changed");
        super::patch_header(&mut output, 4, 4, b"BODY", changed.clone()).unwrap();
        assert_eq!(output.get_ref(), b"headBODYtail");
        assert_eq!(output.position(), 12);

        for wrong in [&b"BOD"[..], b"BODY!"] {
            let error = super::patch_header(&mut output, 4, 4, wrong, changed.clone());
            assert_eq!(error.unwrap_err(), changed);
            assert_eq!(output.get_ref(), b"headBODYtail");
            assert_eq!(output.position(), 12);
        }
    }

    #[test]
    fn managed_memory_quotas_are_refused_by_name() {
        let family = crate::ArchiveFamily::Rar13;
        super::refuse_managed_memory(&crate::WriterResources::default(), family).unwrap();
        for (resources, feature) in [
            (
                crate::WriterResources::default().with_max_preparation_bytes(1 << 20),
                "preparation memory quota",
            ),
            (
                crate::WriterResources::default().with_max_memory_bytes(1 << 20),
                "aggregate managed-memory limit",
            ),
        ] {
            assert_eq!(
                super::refuse_managed_memory(&resources, family).unwrap_err(),
                Error::UnsupportedFamilyFeature { family, feature }
            );
        }
    }

    #[test]
    fn member_error_preserves_cancellation_and_existing_context() {
        assert_eq!(
            super::member_error(crate::Error::Cancelled, b"file", "writing"),
            crate::Error::Cancelled
        );
        let existing =
            crate::Error::InvalidArgument("source failed").at_entry(b"file".to_vec(), "reading");
        let error = super::member_error(existing, b"file", "writing");
        assert_eq!(error.entry_context(), Some((b"file".as_slice(), "reading")));
    }

    use super::*;

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn oversized_member_is_refused_before_opening_its_source() {
        let length = u64::from(u32::MAX) + 1;
        let source = EntrySource::from_opener(length, || {
            panic!("an unrepresentable member must not open its source")
        });
        let member = MemberBytes::Source(&source);
        assert_eq!(member.len().unwrap(), length);
        assert_eq!(
            member.load().unwrap_err(),
            Error::InvalidArgument("member is larger than this host can hold")
        );
    }

    #[test]
    fn changed_sources_are_bounded_and_rejected() {
        use std::io::{Cursor, Seek, SeekFrom};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct Counted {
            data: Cursor<Vec<u8>>,
            read: Arc<AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.data.read(buffer)?;
                self.read.fetch_add(count, Ordering::Relaxed);
                Ok(count)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                self.data.seek(position)
            }
        }

        for expected in [0, 8] {
            for actual in [0, 3, 8, 1024 * 1024] {
                let read = Arc::new(AtomicUsize::new(0));
                let source = EntrySource::from_opener(expected, {
                    let read = Arc::clone(&read);
                    move || {
                        Ok(Box::new(Counted {
                            data: Cursor::new(vec![42; actual]),
                            read: Arc::clone(&read),
                        }))
                    }
                });
                let bytes = MemberBytes::Source(&source);
                let valid = actual as u64 == expected;
                assert_eq!(bytes.load().is_ok(), valid);
                assert!(read.swap(0, Ordering::Relaxed) as u64 <= expected + 1);
                let mut visited = 0;
                assert_eq!(bytes.walk(|chunk| visited += chunk.len()).is_ok(), valid);
                assert!(visited as u64 <= expected);
                assert!(read.swap(0, Ordering::Relaxed) as u64 <= expected + 1);
                let mut output = Vec::new();
                assert_eq!(
                    MemberPayload::Copied(&source)
                        .write_to(&mut output, expected)
                        .is_ok(),
                    valid
                );
                assert!(output.len() as u64 <= expected);
                assert!(read.load(Ordering::Relaxed) as u64 <= expected + 1);
            }
        }
    }

    #[test]
    fn a_source_walks_in_chunks_and_loads_whole() {
        let data: Vec<u8> = (0..WALK_CHUNK * 2 + 7).map(|index| index as u8).collect();
        let source = EntrySource::from_bytes(data.clone());
        let bytes = MemberBytes::Source(&source);

        assert_eq!(bytes.len().unwrap(), data.len() as u64);
        assert_eq!(bytes.load().unwrap().as_ref(), data.as_slice());

        let mut chunks = Vec::new();
        let mut seen = Vec::new();
        bytes
            .walk(|chunk| {
                chunks.push(chunk.len());
                seen.extend_from_slice(chunk);
            })
            .unwrap();
        assert_eq!(seen, data);
        assert!(chunks.len() > 1, "a large source should arrive in pieces");
    }

    #[test]
    fn borrowed_bytes_are_never_copied() {
        let data = b"already in memory".to_vec();
        let bytes = MemberBytes::Borrowed(&data);
        assert!(matches!(bytes.load().unwrap(), Cow::Borrowed(_)));
        assert!(bytes.source().is_none());
        let mut visited = Vec::new();
        bytes
            .walk(|chunk| visited.extend_from_slice(chunk))
            .unwrap();
        assert_eq!(visited, data);
    }
}
