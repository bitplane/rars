#![cfg(all(
    feature = "write",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]

use rars::{
    Archive, ArchiveMemberRef, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ErrorKind, ExtractionErrorAction, MemberReader, MembersIter, ReadCancellation,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::ops::Range;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const CHUNK: usize = 64 * 1024;
const PASSWORD: &[u8] = b"member reader password";

fn build(builder: Builder, members: &[Vec<u8>]) -> Vec<u8> {
    let mut builder = builder;
    for (index, bytes) in members.iter().enumerate() {
        builder
            .add_bytes(
                format!("member-{index:03}").into_bytes(),
                bytes.clone(),
                None,
                None,
            )
            .unwrap();
    }
    builder.to_bytes().unwrap()
}

fn samples() -> Vec<Vec<u8>> {
    (0..3)
        .map(|index| {
            format!("Synthetic member {index}: alpha beta gamma delta\n")
                .repeat(2100)
                .into_bytes()
        })
        .collect()
}

fn packed_range(archive: &Archive, index: usize) -> Range<usize> {
    match archive.member_refs().nth(index).unwrap() {
        ArchiveMemberRef::Rar13(entry) => entry.packed_range.clone(),
        ArchiveMemberRef::Rar15To40(file) => file.packed_range.clone(),
        ArchiveMemberRef::Rar50Plus(file) => file.block.data_range.clone(),
        _ => unreachable!("unexpected archive family"),
    }
}

fn read_in_chunks(mut reader: impl Read, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; size];
    let mut output = Vec::new();
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(output);
        }
        output.extend_from_slice(&buf[..n]);
    }
}

fn check_single_members(version: ArchiveVersion, store: bool, solid: bool, encrypted: bool) {
    let password = encrypted.then_some(PASSWORD);
    let inputs = samples();
    let mut archive = ArchiveReader::read_owned(build(
        Builder::new(version)
            .store(store)
            .solid(solid && !store)
            .password(password.map(<[u8]>::to_vec)),
        &inputs,
    ))
    .unwrap();
    // Builder requires compression for solid output. Mark the parsed main
    // header solid to exercise stored payloads under the same admission policy.
    if solid && store {
        match &mut archive {
            Archive::Rar13(archive) => archive.main.flags |= 0x08,
            Archive::Rar15To40(archive) => archive.main.flags |= 0x0008,
            Archive::Rar50Plus(archive) => archive.main.archive_flags |= 0x0004,
            _ => unreachable!("unexpected archive family"),
        }
    }
    assert_eq!(archive.is_solid(), solid);
    for (index, (member, input)) in archive.members().zip(inputs).enumerate() {
        let context = format!(
            "{version}, store={store}, solid={solid}, encrypted={encrypted}, index={index}"
        );
        assert_eq!(member.meta.is_stored, store, "{context}");
        assert_eq!(member.meta.is_encrypted, encrypted, "{context}");
        let expected = archive.read_member_at(index, password).unwrap().unwrap();
        assert_eq!(input, expected, "{context}");
        for chunk in [1, 7, CHUNK + 3] {
            let options = ArchiveReadOptions::with_optional_password(password);
            let reader = archive.open_member(index, options).unwrap();
            assert_eq!(reader.is_seekable(), store && !encrypted, "{context}");
            assert_eq!(
                read_in_chunks(reader, chunk).unwrap(),
                expected,
                "{context}"
            );
        }
    }
}

#[test]
fn matches_read_member_at_across_formats() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for solid in [false, true] {
            for store in [false, true] {
                check_single_members(version, store, solid, false);
            }
        }
    }
}

#[cfg(feature = "encryption")]
#[test]
fn matches_read_member_at_with_owned_password() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        for solid in [false, true] {
            for store in [false, true] {
                check_single_members(version, store, solid, true);
            }
        }
    }
    let mut password = PASSWORD.to_vec();
    let inputs = samples();
    let archive = ArchiveReader::read_owned(build(
        Builder::new(ArchiveVersion::Rar50).password(Some(password.clone())),
        &inputs,
    ))
    .unwrap();
    let options = ArchiveReadOptions::with_password(&password);
    let reader = archive.open_member(0, options).unwrap();
    let iter = archive.read_members_iter(&[2, 1, 1], options).unwrap();
    password.fill(0);
    drop(archive);
    assert_eq!(read_in_chunks(reader, 7).unwrap(), inputs[0]);
    assert_eq!(
        iter.collect::<rars::Result<Vec<_>>>().unwrap(),
        vec![(1, inputs[1].clone()), (2, inputs[2].clone())]
    );
}

#[test]
fn stored_seeks_match_cursor_on_memory_and_reader_sources() {
    let data: Vec<u8> = (0..9000).map(|i| (i ^ (i >> 7)) as u8).collect();
    let bytes = build(
        Builder::new(ArchiveVersion::Rar50).store(true),
        std::slice::from_ref(&data),
    );
    for archive in [
        ArchiveReader::read(&bytes).unwrap(),
        ArchiveReader::read_reader(Cursor::new(bytes)).unwrap(),
    ] {
        let mut reader = archive.open_member(0, ArchiveReadOptions::new()).unwrap();
        drop(archive);
        assert!(reader.is_seekable());
        let mut expected = Cursor::new(&data);
        let mut random = 42_u32;
        for _ in 0..32 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let position = u64::from(random % 8500) + 100;
            for from in [
                SeekFrom::Start(position),
                SeekFrom::Current(-29),
                SeekFrom::End(position as i64 - 9000),
            ] {
                assert_eq!(reader.seek(from).unwrap(), expected.seek(from).unwrap());
                let mut actual = [0; 17];
                let mut wanted = [0; 17];
                reader.read_exact(&mut actual).unwrap();
                expected.read_exact(&mut wanted).unwrap();
                assert_eq!(actual, wanted);
            }
        }
        assert_eq!(reader.seek(SeekFrom::End(20)).unwrap(), 9020);
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
        assert_eq!(
            reader.seek(SeekFrom::End(-9001)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(reader.stream_position().unwrap(), 9020);
    }
}

#[test]
fn compressed_seeks_only_to_current_position() {
    let data = samples();
    let archive =
        ArchiveReader::read_owned(build(Builder::new(ArchiveVersion::Rar50), &data)).unwrap();
    let mut reader = archive.open_member(0, ArchiveReadOptions::new()).unwrap();
    assert!(!reader.is_seekable());
    assert_eq!(reader.stream_position().unwrap(), 0);
    let mut first = [0; 7];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(reader.stream_position().unwrap(), 7);
    assert_eq!(reader.seek(SeekFrom::Start(7)).unwrap(), 7);
    assert_eq!(
        reader
            .seek(SeekFrom::End(7 - data[0].len() as i64))
            .unwrap(),
        7
    );
    for from in [SeekFrom::Start(0), SeekFrom::Current(1), SeekFrom::End(0)] {
        assert_eq!(
            reader.seek(from).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
    assert_eq!(read_in_chunks(reader, CHUNK + 3).unwrap(), &data[0][7..]);
}

fn damaged_archive(store: bool, blake2sp: bool) -> (Archive, Vec<Vec<u8>>) {
    let inputs = samples();
    let mut bytes = build(
        Builder::new(ArchiveVersion::Rar50)
            .store(store)
            .blake2sp(blake2sp),
        &inputs,
    );
    let archive = ArchiveReader::read(&bytes).unwrap();
    let range = packed_range(&archive, 1);
    if store {
        bytes[range.start] ^= 1;
        return (ArchiveReader::read_owned(bytes).unwrap(), inputs);
    }
    // Find a packed-bit change that leaves a decodable stream with bad data.
    // Other mutations can damage the code tables and fail before the checksum.
    for offset in range {
        for bit in 0..8 {
            bytes[offset] ^= 1 << bit;
            let damaged = ArchiveReader::read(&bytes).unwrap();
            if damaged
                .read_member_at(1, None)
                .is_err_and(|error| error.kind() == ErrorKind::ChecksumMismatch)
            {
                return (damaged, inputs);
            }
            bytes[offset] ^= 1 << bit;
        }
    }
    panic!("no packed bit produced a checksum mismatch");
}

fn checksum_error(error: io::Error) -> Error {
    let error = error.downcast::<Error>().unwrap();
    assert_eq!(error.kind(), ErrorKind::ChecksumMismatch);
    error
}

#[test]
fn stored_checksums_fail_on_the_read_that_reaches_the_end() {
    for blake2sp in [false, true] {
        let (archive, inputs) = damaged_archive(true, blake2sp);
        let options = ArchiveReadOptions::new();
        let mut reader = archive.open_member(1, options).unwrap();
        reader
            .read_exact(&mut vec![0; inputs[1].len() - 1])
            .unwrap();
        let error = checksum_error(reader.read(&mut [0; 7]).unwrap_err());
        assert_eq!(
            matches!(error.root_cause(), Error::HashMismatch { .. }),
            blake2sp
        );
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
        let mut reader = archive.open_member(1, options).unwrap();
        assert_eq!(reader.stream_position().unwrap(), 0);
        let data = read_in_chunks(reader, 7).unwrap();
        assert_eq!(data.len(), inputs[1].len());
        assert_ne!(data, inputs[1]);
        for index in [0, 2] {
            assert_eq!(
                read_in_chunks(archive.open_member(index, options).unwrap(), 7).unwrap(),
                inputs[index]
            );
        }
    }
}

#[test]
fn compressed_checksum_failure_follows_the_decoded_prefix() {
    let (archive, inputs) = damaged_archive(false, false);
    let options = ArchiveReadOptions::new()
        .with_threads(1)
        .with_rar50_buffered_decode_limit(0);
    let mut reader = archive.open_member(1, options).unwrap();
    let mut output = Vec::new();
    checksum_error(reader.read_to_end(&mut output).unwrap_err());
    assert_eq!(output.len(), inputs[1].len());
    assert_ne!(output, inputs[1]);
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    for index in [0, 2] {
        assert_eq!(
            read_in_chunks(archive.open_member(index, options).unwrap(), 7).unwrap(),
            inputs[index]
        );
    }
}

#[test]
fn large_member_streams_and_can_be_dropped_mid_read() {
    let data = b"0123456789abcdef".repeat(16 * 1024 * 1024 / 16);
    let archive = ArchiveReader::read_owned(build(
        Builder::new(ArchiveVersion::Rar50),
        std::slice::from_ref(&data),
    ))
    .unwrap();
    assert!(!archive.members().next().unwrap().meta.is_stored);
    let options = ArchiveReadOptions::new()
        .with_threads(1)
        .with_rar50_buffered_decode_limit(0);
    let mut reader = archive.open_member(0, options).unwrap();
    let mut buffer = vec![0; CHUNK + 3];
    let mut offset = 0;
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        assert_eq!(&buffer[..count], &data[offset..offset + count]);
        offset += count;
    }
    assert_eq!(offset, data.len());

    let mut reader = archive.open_member(0, options).unwrap();
    reader.read_exact(&mut [0; 7]).unwrap();
    // Leave the consumer idle while the producer has megabytes left to send.
    std::thread::sleep(Duration::from_millis(100));
    assert_prompt_drop(reader);
}

fn assert_prompt_drop(value: impl Send) {
    let (done, finished) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            drop(value);
            done.send(()).unwrap();
        });
        finished.recv_timeout(Duration::from_secs(10)).unwrap();
    });
}

struct ObservedSource {
    bytes: Cursor<Vec<u8>>,
    reads: Arc<Mutex<Vec<Range<usize>>>>,
}

impl Read for ObservedSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.bytes.position() as usize;
        let count = self.bytes.read(buf)?;
        if count != 0 {
            self.reads.lock().unwrap().push(start..start + count);
        }
        Ok(count)
    }
}

impl Seek for ObservedSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(from)
    }
}

#[test]
fn solid_iterator_traverses_each_packed_payload_once() {
    let inputs: Vec<_> = (0..200)
        .map(|i| {
            format!("Page {i} in a synthetic text archive.\n")
                .repeat(30)
                .into_bytes()
        })
        .collect();
    let reads = Arc::new(Mutex::new(Vec::new()));
    let archive = ArchiveReader::read_reader(ObservedSource {
        bytes: Cursor::new(build(
            Builder::new(ArchiveVersion::Rar29).solid(true),
            &inputs,
        )),
        reads: Arc::clone(&reads),
    })
    .unwrap();
    assert!(archive.members().skip(1).all(|member| member.is_solid()));
    let selection: Vec<_> = (0..200).collect();
    let expected = archive.read_members_at(&selection, None).unwrap();
    let mut unordered: Vec<_> = selection.iter().copied().rev().collect();
    unordered.extend([8, 9, usize::MAX]);
    reads.lock().unwrap().clear();
    let options = ArchiveReadOptions::new().with_threads(1);
    let actual = archive
        .read_members_iter(&unordered, options)
        .unwrap()
        .collect::<rars::Result<Vec<_>>>()
        .unwrap();
    for (index, (actual_index, bytes)) in actual.iter().enumerate() {
        assert_eq!(*actual_index, index);
        assert_eq!(Some(bytes), expected[index].as_ref());
        assert_eq!(*bytes, inputs[index]);
    }
    assert_eq!(actual.len(), selection.len());

    let reads = reads.lock().unwrap();
    for index in selection {
        let packed = packed_range(&archive, index);
        let bytes_read: usize = reads
            .iter()
            .map(|read| {
                packed
                    .end
                    .min(read.end)
                    .saturating_sub(packed.start.max(read.start))
            })
            .sum();
        assert_eq!(bytes_read, packed.len(), "packed input for member {index}");
    }
}

#[test]
fn sparse_solid_reads_keep_history_and_charge_predecessors() {
    let inputs = samples();
    let archive = ArchiveReader::read_owned(build(
        Builder::new(ArchiveVersion::Rar50).solid(true),
        &inputs,
    ))
    .unwrap();
    let options = ArchiveReadOptions::new();
    let mut iter = archive.read_members_iter(&[2, 2], options).unwrap();
    assert_eq!(iter.next().unwrap().unwrap(), (2, inputs[2].clone()));
    assert!(iter.next().is_none());

    let limited = options.with_max_total_output_bytes(inputs[0].len() as u64);
    let mut iter = archive.read_members_iter(&[2], limited).unwrap();
    assert_eq!(
        iter.next().unwrap().unwrap_err().kind(),
        ErrorKind::ResourceLimit
    );
    assert!(iter.next().is_none());
    let mut reader = archive.open_member(2, limited).unwrap();
    assert_eq!(
        reader
            .read(&mut [0; 1])
            .unwrap_err()
            .downcast::<Error>()
            .unwrap()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_prompt_drop(archive.read_members_iter(&[0, 1, 2], options).unwrap());
}

#[test]
fn independent_iterator_recovers_after_member_error() {
    let (archive, inputs) = damaged_archive(false, false);
    let mut iter = archive
        .read_members_iter(&[2, 0, 1, 2], ArchiveReadOptions::new())
        .unwrap();
    assert_eq!(iter.next().unwrap().unwrap(), (0, inputs[0].clone()));
    assert_eq!(
        iter.next().unwrap().unwrap_err().kind(),
        ErrorKind::ChecksumMismatch
    );
    assert_eq!(iter.next().unwrap().unwrap(), (2, inputs[2].clone()));
    assert!(iter.next().is_none());
}

#[test]
fn options_and_non_payload_indices() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .add_unix_symlink(b"link".to_vec(), b"dir".to_vec(), true, None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(build(builder, &[Vec::new()])).unwrap();
    let token = ReadCancellation::new();
    let handler = |_: &rars::ArchiveMember, _: &Error| Ok(ExtractionErrorAction::Continue);
    for options in [
        ArchiveReadOptions::new().with_cancellation(&token),
        ArchiveReadOptions::new().with_member_error_handler(&handler),
    ] {
        for error in [
            archive.open_member(2, options).err().unwrap(),
            archive.read_members_iter(&[2], options).err().unwrap(),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
            assert!(error.to_string().contains("drop the reader or iterator"));
        }
    }
    let options = ArchiveReadOptions::new();
    for (index, member) in archive.members().enumerate() {
        if member.meta.is_directory || member.meta.is_redirection {
            assert_eq!(
                archive.open_member(index, options).err().unwrap().kind(),
                ErrorKind::InvalidArgument
            );
        }
    }
    assert_eq!(
        archive.open_member(99, options).err().unwrap().kind(),
        ErrorKind::InvalidArgument
    );
    let members = archive
        .read_members_iter(&[0, 1, 2, 99], options)
        .unwrap()
        .collect::<rars::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0].1.is_empty());
}

#[cfg(feature = "parallel")]
#[test]
fn bytes_match_at_one_two_and_many_threads() {
    let inputs: Vec<_> = samples()
        .into_iter()
        .map(|bytes| bytes.repeat(12))
        .collect();
    let archive = ArchiveReader::read_owned(build(
        Builder::new(ArchiveVersion::Rar50).solid(true),
        &inputs,
    ))
    .unwrap();
    for threads in [1, 2, 8] {
        let options = ArchiveReadOptions::new()
            .with_threads(threads)
            .with_rar50_buffered_decode_limit(0);
        let reader = archive.open_member(2, options).unwrap();
        assert_eq!(read_in_chunks(reader, CHUNK + 3).unwrap(), inputs[2]);
        let iter = archive.read_members_iter(&[0, 1, 2], options).unwrap();
        assert_eq!(
            iter.collect::<rars::Result<Vec<_>>>().unwrap(),
            inputs.iter().cloned().enumerate().collect::<Vec<_>>()
        );
    }
}

#[test]
fn readers_are_send_and_static() {
    fn require<T: Send + 'static>() {}
    require::<MemberReader>();
    require::<MembersIter>();
}
