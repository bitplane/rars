use rars::codec::rar13::*;

#[test]
fn normal_encoder_round_trips_terminal_literal_flag_groups() {
    for length in [23, 24, 25] {
        let input: Vec<u8> = (0..length).collect();
        let packed = rars::codec::rar13::unpack15_encode(&input).unwrap();
        assert_eq!(
            rars::codec::rar13::unpack15_decode(&packed, input.len()).unwrap(),
            input
        );
    }
}

#[test]
fn public_decoder_clone_keeps_independent_solid_history_and_tables() {
    let first = b"legacy adaptive solid history ".repeat(32);
    let second = b"legacy adaptive solid history ".repeat(8);
    let mut encoder = rars::codec::rar13::Unpack15Encoder::new();
    let packed_first = encoder.encode_member(&first).unwrap();
    let packed_second = encoder.encode_member(&second).unwrap();
    let mut original = rars::codec::rar13::Unpack15::new();
    assert_eq!(
        original
            .decode_member(&packed_first, first.len(), false)
            .unwrap(),
        first
    );
    let mut copied = original.clone();
    let other = b"a different non-solid member";
    assert_eq!(
        original
            .decode_member(
                &rars::codec::rar13::unpack15_encode(other).unwrap(),
                other.len(),
                false
            )
            .unwrap(),
        other
    );
    drop(original);
    assert_eq!(
        copied
            .decode_member(&packed_second, second.len(), true)
            .unwrap(),
        second
    );
}

#[test]
fn probe_rar15_solid() {
    let Ok(dir) = std::env::var("RARS_PROBE_DIR") else {
        return;
    };
    let options = EncodeOptions::new().with_lazy_matching(false);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    let mut enc = Unpack15Encoder::with_options(options);
    let mut dec = Unpack15::new();
    for path in &names {
        let data = std::fs::read(path).unwrap();
        let packed = enc.encode_member(&data).unwrap();
        match dec.decode_member(&packed, data.len(), true) {
            Ok(out) if out == data => println!("{:?} solid OK", path.file_name().unwrap()),
            Ok(out) => println!(
                "{:?} solid WRONG at {:?}",
                path.file_name().unwrap(),
                out.iter().zip(data.iter()).position(|(a, b)| a != b)
            ),
            Err(e) => println!("{:?} solid ERROR {e:?}", path.file_name().unwrap()),
        }
    }
}

#[test]
fn decode_member_from_reader_accepts_incremental_input() {
    struct TinyReader<'a> {
        input: &'a [u8],
    }

    impl std::io::Read for TinyReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.input.is_empty() {
                return Ok(0);
            }
            let len = self.input.len().min(out.len()).min(2);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    let expected = b"RAR 1.4 incremental input fixture\n".repeat(32);
    let packed = unpack15_encode(&expected).unwrap();
    assert_eq!(unpack15_decode(&packed, expected.len()).unwrap(), expected);

    let mut reader = TinyReader { input: &packed };
    let mut decoder = Unpack15::new();
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, expected.len(), false, &mut output)
        .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn literal_only_encoder_round_trips_flag_and_mode_boundaries() {
    for length in 0..=96 {
        let input: Vec<u8> = (0..length)
            .map(|index| (index * 73 + length * 17) as u8)
            .collect();
        let packed = Unpack15Encoder::new().encode_literals_only(&input).unwrap();
        let decoded = unpack15_decode(&packed, input.len()).unwrap();
        assert_eq!(decoded, input, "literal-only length {length}");
    }
}

#[test]
fn final_input_zero_pads_missing_bits_in_both_decode_paths() {
    let mut decoder = Unpack15::new();
    let direct = decoder.decode_member(&[], 8, false).unwrap();
    assert_eq!(direct.len(), 8);

    let mut decoder = Unpack15::new();
    let mut from_reader = Vec::new();
    decoder
        .decode_member_from_reader(&mut &[][..], 8, false, &mut from_reader)
        .unwrap();
    assert_eq!(from_reader, direct);
}

#[test]
fn encoder_emits_rar15_very_long_lz_matches() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..258);

    assert_eq!(
        find_long_lz(&input, 300, 0x8000),
        Some(LongLz {
            distance: 300,
            length: 258
        })
    );
    let packed = unpack15_encode(&input).unwrap();

    assert!(
        packed.len() < 330,
        "very-long LongLZ should encode a 258-byte repeat compactly, got {} bytes",
        packed.len()
    );
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn long_lz_search_accepts_near_distance_boundaries() {
    let distance_one = vec![b'A'; 64];
    assert_eq!(
        find_long_lz(&distance_one, 1, 0x8000),
        Some(LongLz {
            distance: 1,
            length: 63,
        })
    );

    let distance_sixteen = b"abcdefghijklmnop".repeat(4);
    assert_eq!(
        find_long_lz(&distance_sixteen, 16, 0x8000),
        Some(LongLz {
            distance: 16,
            length: 48,
        })
    );

    let distance_256: Vec<_> = (0u8..=255).cycle().take(512).collect();
    assert_eq!(
        find_long_lz(&distance_256, 256, 0x8000),
        Some(LongLz {
            distance: 256,
            length: 256,
        })
    );
}

#[test]
fn near_long_lz_requires_the_eleven_byte_wire_minimum() {
    let input = b"abcdefghijXabcdefghijY";

    assert_eq!(find_long_lz(input, 11, 0x8000), None);
}

#[test]
fn distance_257_remains_a_far_long_lz_match() {
    let mut state = 0x1234_5678u32;
    let mut input: Vec<_> = (0..257)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let repeated = input[..32].to_vec();
    input.extend_from_slice(&repeated);

    assert_eq!(
        find_long_lz(&input, 257, 0x8000),
        Some(LongLz {
            distance: 257,
            length: 32,
        })
    );
}

#[test]
fn encoder_adjusts_rar15_long_lz_length_for_far_distance_bonus() {
    let mut input: Vec<_> = (0..9000).map(|index| (index * 73 + 19) as u8).collect();
    input.extend_from_within(..10);

    let packed = unpack15_encode(&input).unwrap();

    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_reuses_rar15_repeat_last_token() {
    let input = b"abcdefghijklmnop".repeat(64);
    let packed = unpack15_encode(&input).unwrap();

    assert!(
        packed.len() < 100,
        "repeat-last tokens should keep a simple repeated pattern compact, got {} bytes",
        packed.len()
    );
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_exits_stmode_when_literal_runs_trigger_decoder_mode() {
    let input: Vec<_> = (0..96).map(|index| (index * 73 + 19) as u8).collect();
    let packed = unpack15_encode(&input).unwrap();

    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_options_bound_long_lz_search_distance() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..64);

    assert_eq!(
        find_long_lz(&input, 300, 256),
        Some(LongLz {
            distance: 44,
            length: 44,
        })
    );
    assert_eq!(
        find_long_lz(&input, 300, 0x8000),
        Some(LongLz {
            distance: 300,
            length: 64
        })
    );
}

#[test]
fn long_lz_search_rejects_unencodable_32k_distance() {
    let mut input = Vec::with_capacity(0x8000 + 64);
    let mut state = 0x1234_5678u32;
    for _ in 0..0x8000 + 64 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 24) as u8);
    }
    let repeated = input[..64].to_vec();
    input[0x8000..0x8000 + 64].copy_from_slice(&repeated);

    let token = find_long_lz(&input, 0x8000, 0x8000);

    assert_ne!(token.map(|token| token.distance), Some(0x8000));
}

#[test]
fn encoder_round_trips_source_shaped_payload() {
    let source = concat!(
        include_str!("../../src/codec/rar13.rs"),
        include_str!("../../src/codec/rar13/encoder.rs")
    )
    .as_bytes();
    let input = &source[..source.len().min(50_902)];

    let packed = unpack15_encode(input).unwrap();
    let decoded = unpack15_decode(&packed, input.len()).unwrap();

    let first_diff = decoded
        .iter()
        .zip(input)
        .position(|(actual, expected)| actual != expected);
    assert_eq!(first_diff, None, "first differing byte in decoded payload");
    assert_eq!(decoded, input);
}

/// Match-heavy input drives `nlzb` above `nhfb`, which widens the literal
/// flag to two bits, which is what lets a flag reach the last bit of a
/// flags byte with a bit still to place. The encoder used to pad the byte
/// and start the next group cleanly; the decoder read that padding as a
/// flag and everything after it decoded to the wrong bytes.
#[test]
fn a_flag_straddling_two_flags_bytes_round_trips() {
    let input = match_heavy_payload(176, 8000);

    let packed =
        unpack15_encode_with_options(&input, EncodeOptions::new().with_lazy_matching(false))
            .unwrap();
    let decoded = unpack15_decode(&packed, input.len()).unwrap();

    let first_diff = decoded
        .iter()
        .zip(&input)
        .position(|(actual, expected)| actual != expected);
    assert_eq!(first_diff, None, "first differing byte in decoded payload");
}

fn match_heavy_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let value = next();
        if out.len() > 4096 && value % 3 != 0 {
            let distance = 64 + (value >> 8) as usize % (out.len() - 64);
            let length = 3 + (value >> 40) as usize % 24;
            let start = out.len() - distance;
            for index in 0..length {
                let byte = out[start + index % distance];
                out.push(byte);
            }
        } else {
            out.push((value >> 24) as u8);
        }
    }
    out.truncate(len);
    out
}
