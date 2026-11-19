use rars::{ArchiveReadOptions, ArchiveReader, Error};
use std::io;

fn vint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn block(body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    vint(body.len() as u64, &mut encoded);
    encoded.extend_from_slice(body);
    let mut block = rars::crc32::crc32(&encoded).to_le_bytes().to_vec();
    block.extend_from_slice(&encoded);
    block
}

fn advertised_member(unpacked_size: u64, compression_info: u64, split_flags: u8) -> rars::Archive {
    let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
    bytes.extend_from_slice(&block(&[1, 0, u8::from(split_flags != 0)]));

    // FILE block: type, header flags, file flags, unpacked size, attributes,
    // compression info, host OS, and the one-byte name. No payload is needed
    // because the advertised lengths must be rejected before decoding.
    let mut file = vec![2, split_flags, 0];
    vint(unpacked_size, &mut file);
    file.push(0);
    vint(compression_info, &mut file);
    file.extend_from_slice(&[0, 1, b'x']);
    bytes.extend_from_slice(&block(&file));
    ArchiveReader::read_owned(bytes).expect("the size declaration must parse")
}

fn assert_invalid_header(error: Error, expected: &'static str) {
    assert!(
        matches!(error.root_cause(), Error::InvalidHeader(message) if *message == expected),
        "expected {expected:?}, got {error:?}"
    );
}

#[test]
fn compressed_declarations_exceeding_32_bit_usize_fail_before_decode() {
    // v0 method 1 with dictionary power 15 advertises exactly 4 GiB. Neither
    // case has a payload large enough to satisfy its declared requirements.
    for (unpacked_size, compression_info, expected) in [
        (
            1u64 << 32,
            0x80,
            "RAR 5 unpacked size overflows host address size",
        ),
        (
            1,
            0x3c80,
            "RAR 5 dictionary size overflows host address size",
        ),
    ] {
        let archive = advertised_member(unpacked_size, compression_info, 0);
        let file = archive.members().next().expect("one file");
        assert_eq!(file.meta.unpacked_size, unpacked_size);
        if usize::BITS >= 64 {
            continue;
        }

        let options = ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
        assert_invalid_header(
            archive
                .extract_to_with_options(options, |_| Ok(Box::new(io::sink())))
                .unwrap_err(),
            expected,
        );
        assert_invalid_header(
            archive
                .extract_to_parallel_buffered_with_options(options, |_| Ok(Box::new(io::sink())))
                .unwrap_err(),
            expected,
        );

        let volumes = [
            advertised_member(unpacked_size, compression_info, 0x10),
            advertised_member(unpacked_size, compression_info, 0x08),
        ];
        assert_invalid_header(
            rars::extract_volumes_to_with_options(&volumes, options, |_| Ok(Box::new(io::sink())))
                .unwrap_err(),
            expected,
        );
    }
}
