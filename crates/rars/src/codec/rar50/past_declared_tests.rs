use super::*;

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn write_bits(&mut self, value: usize, count: usize) {
        for bit in (0..count).rev() {
            if self.len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if value >> bit & 1 != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }
}

// Every code is two bits: A 00, B 01, filter 10, match 11 (length 2, distance 2).
fn writer() -> Bits {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 2;
    lengths.main[b'B' as usize] = 2;
    lengths.main[256] = 2;
    lengths.main[262] = 2;
    lengths.distance[1] = 1;
    let (bytes, len) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    Bits { bytes, len }
}

fn literals(writer: &mut Bits, text: &[u8]) {
    for &byte in text {
        match byte {
            b'A' => writer.write_bits(0b00, 2),
            b'B' => writer.write_bits(0b01, 2),
            _ => panic!("only A and B have codes"),
        }
    }
}

fn a_match(writer: &mut Bits) {
    writer.write_bits(0b11, 2);
    writer.write_bits(0, 1);
}

// A filter over 8 bytes from the position it is read at; kind 0 is delta.
fn filter_record(writer: &mut Bits, kind: usize) {
    writer.write_bits(0b10, 2);
    writer.write_bits(0, 2);
    writer.write_bits(0, 8);
    writer.write_bits(0, 2);
    writer.write_bits(8, 8);
    writer.write_bits(kind, 3);
    if kind == 0 {
        writer.write_bits(0, 5);
    }
}

fn block(writer: Bits, has_tables: bool, is_last: bool) -> Vec<u8> {
    encode_compressed_block(&writer.bytes, writer.len, has_tables, is_last).unwrap()
}

fn single_block(build: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut writer = writer();
    build(&mut writer);
    block(writer, true, true)
}

// The buffered decoder, then the streamed one serially and with block workers.
fn decode_every_way(stream: &[u8], declared: usize) -> Vec<Result<Vec<u8>>> {
    let mut outcomes = vec![Unpack50Decoder::new().decode_member_with_dictionary(
        stream,
        0,
        declared,
        DEFAULT_DICTIONARY_SIZE,
        false,
        DecodeMode::Lz,
    )];
    for workers in [0, 1, 4] {
        let mut out = Vec::new();
        let result = Unpack50Decoder::new()
            .with_decode_workers(workers)
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut &*stream,
                0,
                declared,
                DEFAULT_DICTIONARY_SIZE,
                false,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => out.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            out.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::convert::Infallible>(())
                },
            );
        outcomes.push(match result {
            Ok(()) => Ok(out),
            Err(StreamDecodeError::Decode(error)) => Err(error),
            Err(error) => panic!("{error:?}"),
        });
    }
    outcomes
}

fn assert_refused(stream: &[u8], declared: usize) {
    for outcome in decode_every_way(stream, declared) {
        assert_eq!(outcome, Err(PAST_DECLARED));
    }
}

fn assert_decodes(stream: &[u8], declared: usize, expected: &[u8]) {
    for outcome in decode_every_way(stream, declared) {
        assert_eq!(outcome.as_deref(), Ok(expected));
    }
}

#[test]
fn a_rar5_member_with_a_literal_past_its_declared_size_is_refused() {
    let stream = single_block(|writer| literals(writer, b"ABAB"));
    assert_refused(&stream, 3);
    assert_refused(&stream, 0);
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn a_rar5_member_with_a_match_past_its_declared_size_is_refused() {
    let stream = single_block(|writer| {
        literals(writer, b"AB");
        a_match(writer);
    });
    assert_refused(&stream, 2);
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn a_literal_after_a_trailing_filter_record_is_refused() {
    let stream = single_block(|writer| {
        literals(writer, b"AB");
        filter_record(writer, 0);
        literals(writer, b"B");
    });
    assert_refused(&stream, 2);
}

#[test]
fn a_trailing_filter_record_with_nothing_after_it_stays_legal() {
    let stream = single_block(|writer| {
        literals(writer, b"ABAB");
        filter_record(writer, 0);
    });
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn an_empty_last_block_stays_legal() {
    let mut first = writer();
    literals(&mut first, b"ABAB");
    let stream = [
        block(first, true, false),
        block(Bits::default(), false, true),
    ]
    .concat();
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn a_last_block_without_the_final_flag_stays_legal() {
    let mut first = writer();
    literals(&mut first, b"ABAB");
    let unflagged = block(first, true, false);
    assert_decodes(&unflagged, 4, b"ABAB");
    assert_decodes(&[&unflagged[..], &[0; 16]].concat(), 4, b"ABAB");
}

#[test]
fn spare_bits_after_the_last_symbol_stay_legal() {
    let mut writer = writer();
    literals(&mut writer, b"ABAB");
    // One spare bit: the zero padding after it would read as A, but no
    // whole code fits before the block's end.
    writer.write_bits(0, 1);
    let stream = block(writer, true, true);
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn zero_padding_after_the_last_symbol_stays_legal() {
    // Zero bits read as A here, but writers pad blocks with them.
    let stream = single_block(|writer| {
        literals(writer, b"ABAB");
        writer.write_bits(0, 32);
    });
    assert_decodes(&stream, 4, b"ABAB");
}

#[test]
fn a_match_that_straddles_the_declared_size_stays_legal() {
    let stream = single_block(|writer| {
        literals(writer, b"AB");
        a_match(writer);
    });
    assert_decodes(&stream, 3, b"ABA");
}

#[test]
fn a_literal_after_a_straddling_match_is_refused() {
    let stream = single_block(|writer| {
        literals(writer, b"AB");
        a_match(writer);
        literals(writer, b"B");
    });
    assert_refused(&stream, 3);
}

#[test]
fn a_trailing_filter_record_of_an_unsupported_type_stays_legal() {
    let stream = single_block(|writer| {
        literals(writer, b"ABAB");
        filter_record(writer, 4);
    });
    assert_decodes(&stream, 4, b"ABAB");
}
