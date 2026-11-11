#![no_main]

//! Decodes the same streams serially and with block-decode workers, which must
//! agree on output, errors and the state a solid successor starts from.

use libfuzzer_sys::fuzz_target;
use rars::codec::rar50::{DecodedChunk, Unpack50Decoder};

const MAX_INPUT_SIZE: usize = 128 * 1024;
const MAX_OUTPUT_SIZE: usize = 128 * 1024;
const MAX_DICTIONARY_SIZE: usize = 512 * 1024;

#[derive(Debug, PartialEq)]
struct Run {
    output: Vec<u8>,
    error: Option<String>,
}

fn decode(
    decoder: &mut Unpack50Decoder,
    packed: &[u8],
    algorithm_version: u8,
    output_size: usize,
    dictionary_size: usize,
    solid: bool,
) -> Run {
    let mut output = Vec::new();
    let result = decoder.decode_member_from_reader_with_dictionary_to_sink(
        &mut &*packed,
        algorithm_version,
        output_size,
        dictionary_size,
        solid,
        |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => output.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => output.resize(output.len() + len, byte),
            }
            Ok::<(), ()>(())
        },
    );
    Run {
        output,
        error: result.err().map(|error| format!("{error:?}")),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let algorithm_version = data[0] & 1;
    let workers = 1 + usize::from(data[0] >> 1 & 3);
    let sizes = [
        1 + usize::from(u16::from_le_bytes([data[1], data[2]])) % MAX_OUTPUT_SIZE,
        1 + usize::from(u16::from_le_bytes([data[3], data[4]])) % MAX_OUTPUT_SIZE,
    ];
    let dictionary_size =
        1 + usize::from(u16::from_le_bytes([data[5], data[6]])) * 8 % MAX_DICTIONARY_SIZE;
    let packed = &data[8..data.len().min(8 + MAX_INPUT_SIZE)];
    // A second, solid member continues from whatever state the first left.
    let split = packed.len() * usize::from(data[7]) / 255;
    let members = [&packed[..split], &packed[split..]];

    let mut serial = Unpack50Decoder::new();
    let mut ahead = Unpack50Decoder::new().with_decode_workers(workers);
    for (index, (member, size)) in members.into_iter().zip(sizes).enumerate() {
        let solid = index == 1;
        let expected = decode(&mut serial, member, algorithm_version, size, dictionary_size, solid);
        let actual = decode(&mut ahead, member, algorithm_version, size, dictionary_size, solid);
        assert_eq!(actual, expected, "member {index}, workers {workers}");
    }
});
