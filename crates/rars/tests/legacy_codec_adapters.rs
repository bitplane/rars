#![cfg(feature = "write")]

use rars::codec::{
    rar13::{Unpack15, Unpack15Encoder},
    rar20::{Unpack20, Unpack20Encoder},
    rar29::{Unpack29, Unpack29Encoder},
};
use std::io::{self, Read, Write};

struct TinyReader<'a>(&'a [u8]);

impl Read for TinyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = out.len().min(self.0.len()).min(3);
        out[..len].copy_from_slice(&self.0[..len]);
        self.0 = &self.0[len..];
        Ok(len)
    }
}

struct FailedReader;

impl Read for FailedReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source refused",
        ))
    }
}

struct FailedWriter;

impl Write for FailedWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn assert_io_error(error: rars::codec::Error, kind: io::ErrorKind, message: &str) {
    let rars::codec::Error::Io(source) = error else {
        panic!("expected an I/O failure, got {error:?}");
    };
    let rars::Error::Io(detail) = *source else {
        panic!("expected the library I/O context, got {source:?}");
    };
    assert_eq!(detail.kind, kind);
    assert_eq!(detail.message, message);
}

fn members() -> (Vec<u8>, Vec<u8>) {
    let phrase = b"legacy solid decoder history alpha beta gamma ";
    (phrase.repeat(8), phrase.repeat(4))
}

#[test]
fn rar29_tiny_x86_filter_members_preserve_incomplete_operands() {
    let bytes = [0xe8, 0xff, 0xe9, 0x01];
    for length in 1..=4 {
        for kind in [rars::FilterKind::E8, rars::FilterKind::E8E9] {
            let input = &bytes[..length];
            let packed = Unpack29Encoder::new()
                .encode_member_with_filter(input, rars::FilterSpec::whole(kind))
                .unwrap();
            let output = Unpack29::default().decode_member(&packed, length).unwrap();
            assert_eq!(output, input);
        }
    }
}

#[test]
fn rar29_x86_filters_round_trip_the_negative_address_wrap_boundary() {
    // Relative +0x00ffffff crosses the 16MiB boundary when the operand's
    // position (one) is added; its coded operand wraps to -1.
    for kind in [rars::FilterKind::E8, rars::FilterKind::E8E9] {
        let input = [0xe8, 0xff, 0xff, 0xff, 0x00];
        let packed = Unpack29Encoder::new()
            .encode_member_with_filter(&input, rars::FilterSpec::whole(kind))
            .unwrap();
        assert_eq!(
            Unpack29::default()
                .decode_member(&packed, input.len())
                .unwrap(),
            input
        );
    }
    assert_eq!(
        Unpack29Encoder::new().encode_member_with_filter(
            b"x",
            rars::FilterSpec::whole(rars::FilterKind::Delta { channels: 0 })
        ),
        Err(rars::codec::Error::InvalidData(
            "RAR 2.9 VM filter channel count is invalid"
        ))
    );
}

#[test]
fn rar15_public_adapters_preserve_cloned_solid_state_and_reset_non_solid_state() {
    let (first, second) = members();
    let mut encoder = Unpack15Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    let mut decoder = Unpack15::default();
    assert_eq!(
        decoder
            .decode_member(&first_packed, first.len(), false)
            .unwrap(),
        first
    );
    let mut copied = decoder.clone();
    let mut output = Vec::new();
    decoder
        .decode_member_to(&second_packed, second.len(), true, &mut output)
        .unwrap();
    assert_eq!(output, second);
    output.clear();
    copied
        .decode_member_from_reader(
            &mut TinyReader(&second_packed),
            second.len(),
            true,
            &mut output,
        )
        .unwrap();
    assert_eq!(output, second);

    let independent = Unpack15Encoder::new().encode_member(&first).unwrap();
    output.clear();
    decoder
        .decode_member_to(&independent, first.len(), false, &mut output)
        .unwrap();
    assert_eq!(output, first);
}

#[test]
fn rar20_public_adapters_preserve_cloned_solid_state() {
    let (first, second) = members();
    let mut encoder = Unpack20Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    let mut decoder = Unpack20::default();
    let mut output = Vec::new();
    decoder
        .decode_member_to(&first_packed, first.len(), &mut output)
        .unwrap();
    assert_eq!(output, first);
    let mut copied = decoder.clone();
    assert_eq!(
        copied.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
    output.clear();
    decoder
        .decode_member_from_reader(&mut TinyReader(&second_packed), second.len(), &mut output)
        .unwrap();
    assert_eq!(output, second);
}

#[test]
fn rar29_public_adapters_preserve_cloned_solid_state_and_reset_each_non_solid_route() {
    let (first, second) = members();
    let mut encoder = Unpack29Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    let mut decoder = Unpack29::default();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    let mut copied = decoder.clone();
    let mut output = Vec::new();
    decoder
        .decode_member_to(&second_packed, second.len(), &mut output)
        .unwrap();
    assert_eq!(output, second);
    output.clear();
    copied
        .decode_member_from_reader(&mut TinyReader(&second_packed), second.len(), &mut output)
        .unwrap();
    assert_eq!(output, second);

    let independent = Unpack29Encoder::new().encode_member(&first).unwrap();
    decoder.reset_non_solid();
    assert_eq!(
        decoder.decode_member(&independent, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_non_solid_member(&independent, first.len())
            .unwrap(),
        first
    );
    output.clear();
    decoder
        .decode_non_solid_member_to(&independent, first.len(), &mut output)
        .unwrap();
    assert_eq!(output, first);
    output.clear();
    decoder
        .decode_non_solid_member_from_reader(
            &mut TinyReader(&independent),
            first.len(),
            &mut output,
        )
        .unwrap();
    assert_eq!(output, first);
}

#[test]
fn rar15_public_adapters_keep_reader_and_sink_failures() {
    let data = b"legacy codec failure context";
    let packed = Unpack15Encoder::new().encode_member(data).unwrap();
    let error = Unpack15::new()
        .decode_member_from_reader(&mut FailedReader, data.len(), false, &mut Vec::new())
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::PermissionDenied, "source refused");
    let error = Unpack15::new()
        .decode_member_to(&packed, data.len(), false, &mut FailedWriter)
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::BrokenPipe, "sink refused");
}

#[test]
fn rar20_public_adapters_keep_reader_and_sink_failures() {
    let data = b"legacy codec failure context";
    let packed = Unpack20Encoder::new().encode_member(data).unwrap();
    let error = Unpack20::new()
        .decode_member_from_reader(&mut FailedReader, data.len(), &mut Vec::new())
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::PermissionDenied, "source refused");
    let error = Unpack20::new()
        .decode_member_to(&packed, data.len(), &mut FailedWriter)
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::BrokenPipe, "sink refused");
}

#[test]
fn rar29_public_adapters_keep_reader_and_sink_failures() {
    let data = b"legacy codec failure context";
    let packed = Unpack29Encoder::new().encode_member(data).unwrap();
    let error = Unpack29::new()
        .decode_member_from_reader(&mut FailedReader, data.len(), &mut Vec::new())
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::PermissionDenied, "source refused");
    let error = Unpack29::new()
        .decode_member_to(&packed, data.len(), &mut FailedWriter)
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::BrokenPipe, "sink refused");
    let error = Unpack29::new()
        .decode_non_solid_member_from_reader(&mut FailedReader, data.len(), &mut Vec::new())
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::PermissionDenied, "source refused");
    let error = Unpack29::new()
        .decode_non_solid_member_to(&packed, data.len(), &mut FailedWriter)
        .unwrap_err();
    assert_io_error(error, io::ErrorKind::BrokenPipe, "sink refused");
}
