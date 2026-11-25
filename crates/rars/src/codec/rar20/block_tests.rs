use super::*;
use crate::codec::rar20::Unpack20;

// Small blocks, so short inputs cross many of them.
const BLOCK: usize = 16 * 1024;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 10] = [
        b"blocks ",
        b"carry ",
        b"their ",
        b"offsets ",
        b"across ",
        b"the ",
        b"table ",
        b"switch, ",
        b"and ",
        b"audio.\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(WORDS[xorshift(&mut state) as usize % WORDS.len()]);
    }
    out.truncate(len);
    out
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len).map(|_| xorshift(&mut state) as u8).collect()
}

// Interleaved 8-bit samples of slow waves, which the audio predictor codes
// far smaller than LZ does.
fn tone(len: usize, channels: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let (t, channel) = ((i / channels) as f64, (i % channels) as f64);
            (128.0 + 90.0 * ((t + 7.0 * channel) / (13.0 + channel)).sin()) as u8
        })
        .collect()
}

fn decode(packed: &[u8], len: usize) -> Vec<u8> {
    Unpack20::new().decode_member(packed, len).unwrap()
}

// Other tests' windows elsewhere in the process would turn nesting off.
fn side_by_side<T: Send>(code: impl FnOnce() -> T + Send) -> T {
    #[cfg(feature = "parallel")]
    return crate::parallel::private_pool(4).install(code);
    #[cfg(not(feature = "parallel"))]
    code()
}

fn levels() -> [EncodeOptions; 3] {
    [
        EncodeOptions::new(8),
        EncodeOptions::default().with_lazy_matching(true),
        EncodeOptions::default().with_optimal_parse(true),
    ]
}

#[test]
fn a_member_of_many_blocks_round_trips_at_every_parse() {
    let data = [text(90_000, 1), noise(20_000, 2), text(50_001, 3)].concat();
    for options in levels() {
        let packed =
            encode_member_in_blocks(&data, &[], None, options, false, None, BLOCK).unwrap();
        assert_eq!(decode(&packed, data.len()), data, "{options:?}");
    }
}

#[test]
fn blocks_switch_between_audio_and_lz_and_keep_both_states() {
    // A block size that does not divide into whole frames moves the channel
    // the next audio block starts on.
    let block = BLOCK + 1;
    let data = [
        tone(40_000, 2),
        text(40_000, 4),
        tone(40_000, 2),
        tone(30_000, 3),
        text(20_000, 5),
    ]
    .concat();
    let options = EncodeOptions::default();
    let mixed = encode_member_in_blocks(&data, &[], None, options, true, None, block).unwrap();
    assert_eq!(decode(&mixed, data.len()), data);
    let lz_only = encode_member_in_blocks(&data, &[], None, options, false, None, block).unwrap();
    let audio_only =
        encode_member_in_blocks(&tone(170_000, 2), &[], None, options, true, None, block).unwrap();
    // Both kinds were chosen: audio where it packs smaller, LZ for the text.
    assert!(mixed.len() < lz_only.len());
    assert!(mixed.len() > audio_only.len());
}

#[test]
fn a_member_of_one_block_codes_as_it_did_whole() {
    // One block is the whole member, with no table switch to announce.
    let data = text(BLOCK, 6);
    for options in levels() {
        let one = encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK).unwrap();
        let two =
            encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK / 2).unwrap();
        assert_eq!(
            one,
            encode_member(&data, &[], None, options, true, None).unwrap()
        );
        assert_ne!(one, two);
        assert_eq!(decode(&two, data.len()), data);
    }
}

fn streamed(
    data: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    try_audio: bool,
) -> (Vec<u8>, usize, Vec<u8>) {
    let mut out = Vec::new();
    let mut chunks = 0;
    let (flow, kept) = encode_streamed(
        &mut &data[..],
        data.len(),
        history,
        fixed_table,
        options,
        try_audio,
        &mut |_| true,
        &mut |bytes, _| {
            out.extend_from_slice(bytes);
            chunks += 1;
            Ok(ControlFlow::Continue(()))
        },
        BLOCK,
    )
    .unwrap();
    assert!(flow.is_continue());
    (out, chunks, kept)
}

#[test]
fn streaming_a_member_writes_what_coding_it_in_memory_does() {
    let data = [text(70_000, 7), tone(30_000, 2), noise(9_999, 8)].concat();
    for options in levels() {
        for try_audio in [false, true] {
            let whole =
                encode_member_in_blocks(&data, &[], None, options, try_audio, None, BLOCK).unwrap();
            let (out, chunks, _) = streamed(&data, &[], None, options, try_audio);
            assert_eq!(out, whole, "{options:?}");
            assert!(chunks > 5, "the packed bytes leave a block at a time");
        }
    }
}

#[test]
fn a_streamed_solid_member_continues_the_chain_as_an_in_memory_one_does() {
    let first = text(30_000, 9);
    let second = [text(40_000, 9), first[..5_000].to_vec()].concat();
    let options = EncodeOptions::default().with_max_match_distance(64 * 1024);
    let table = FixedEncodeTable::new(false);
    let mut chain = Unpack20Encoder::with_options(options);
    let packed_first = chain.encode_member(&first).unwrap();

    let whole = encode_member_in_blocks(
        &second,
        &chain.history,
        Some(table),
        chain.options,
        false,
        None,
        BLOCK,
    )
    .unwrap();
    let (out, _, kept) = streamed(&second, &chain.history, Some(table), chain.options, false);
    assert_eq!(out, whole);
    let mut joined = [chain.history.clone(), second.clone()].concat();
    joined.drain(..joined.len() - 64 * 1024);
    assert_eq!(kept, joined);

    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&packed_first, first.len()).unwrap(),
        first
    );
    assert_eq!(decoder.decode_member(&out, second.len()).unwrap(), second);
}

#[test]
fn a_streamed_chain_moves_on_only_when_every_byte_is_taken() {
    let data = text(3 * BLOCK_SIZE / 2, 10);
    let mut chain = Unpack20Encoder::new();
    chain.encode_member(b"the chain starts here").unwrap();
    let before = chain.history.clone();
    let mut taken = 0;
    let flow = chain
        .encode_member_streamed(
            &mut &data[..],
            data.len(),
            &mut |_| true,
            &mut |bytes, _| {
                taken += bytes.len();
                Ok(ControlFlow::Break(()))
            },
        )
        .unwrap();
    assert!(flow.is_break());
    assert!(taken > 0);
    assert_eq!(chain.history, before);

    let flow = chain
        .encode_member_streamed(&mut &data[..], data.len(), &mut |_| true, &mut |_, _| {
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
    assert!(flow.is_continue());
    // The chain keeps one dictionary of what it has coded.
    let joined = [&before[..], &data[..]].concat();
    assert!(chain.history == joined[joined.len() - chain.options.max_match_distance..]);
}

#[test]
fn streaming_reports_progress_through_the_member_and_can_be_cancelled() {
    let data = text(5 * BLOCK, 11);
    let mut furthest = 0;
    let mut out = Vec::new();
    let (flow, _) = encode_streamed(
        &mut &data[..],
        data.len(),
        &[],
        None,
        EncodeOptions::default(),
        false,
        &mut |at| {
            furthest = furthest.max(at);
            true
        },
        &mut |bytes, _| {
            out.extend_from_slice(bytes);
            Ok(ControlFlow::Continue(()))
        },
        BLOCK,
    )
    .unwrap();
    assert!(flow.is_continue());
    assert_eq!(furthest, data.len());

    let cancelled = encode_streamed(
        &mut &data[..],
        data.len(),
        &[],
        None,
        EncodeOptions::default(),
        false,
        &mut |at| at < 2 * BLOCK,
        &mut |_, _| Ok(ControlFlow::Continue(())),
        BLOCK,
    );
    assert!(matches!(cancelled, Err(Error::Cancelled)));
}

#[test]
fn an_audio_block_with_fewer_channels_starts_again_at_the_first() {
    // Ends with the third channel next, which a two-channel block lacks.
    let first = tone(3 * 1000 + 2, 3);
    let second = tone(2000, 2);
    let (a, coder) = code_audio_block(&first, 3, AudioCoder::default(), true).unwrap();
    assert_eq!(coder.channel, 2);
    let (b, _) = code_audio_block(&second, 2, coder, false).unwrap();
    let mut bits = BitWriter::default();
    bits.append(&a);
    bits.append(&b);
    let data = [first, second].concat();
    assert_eq!(decode(&bits.finish(), data.len()), data);
}

#[test]
fn every_byte_of_a_member_is_counted_once_whatever_the_level() {
    let data = [text(50_000, 13), noise(20_000, 14), text(30_000, 15)].concat();
    for options in levels() {
        // As the writer counts it: progress since the last report, from zero
        // again if a report goes back.
        let (mut last, mut counted) = (0usize, 0usize);
        let mut advance = |position: usize| {
            if position < last {
                last = 0;
            }
            counted += position - last;
            last = position;
            true
        };
        encode_member_in_blocks(&data, &[], None, options, true, Some(&mut advance), BLOCK)
            .unwrap();
        assert_eq!(counted, data.len(), "{options:?}");
    }
}

#[test]
fn solid_rar20_level_three_keeps_the_ladder() {
    use crate::rar15_40::{write_compressed_archive, Archive, FileEntry, WriterOptions};
    use crate::{ArchiveVersion, FeatureSet};

    let prose = text(16 * 1024, 7);
    let header: String = (0..128)
        .map(|i| format!("#define OPTION_{i} {}\n", i % 16))
        .collect();
    let mut state = 0x6772_0001;
    let grey: Vec<_> = (0..256)
        .flat_map(|y| (0..512).map(move |x| (x + y) / 8))
        .map(|shade| (shade + (xorshift(&mut state) % 4) as usize) as u8)
        .collect();

    let members = [
        (b"text.txt".as_slice(), prose.as_slice()),
        (b"options.h".as_slice(), header.as_bytes()),
        (b"grey.raw".as_slice(), grey.as_slice()),
    ];
    let entries = members.map(|(name, data)| FileEntry {
        name,
        data,
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    });
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let options = WriterOptions::new(ArchiveVersion::Rar20, features);
    let encode =
        |level| write_compressed_archive(&entries, options.with_compression_level(level)).unwrap();
    let (two, three) = (encode(2), encode(3));
    assert!(
        three.len() <= two.len(),
        "level 3 {} bytes, level 2 {}",
        three.len(),
        two.len()
    );

    let packed = Archive::parse(&three).unwrap();
    assert!(packed.main.is_solid());
    let mut decoder = Unpack20::new();
    let files: Vec<_> = packed.files().collect();
    assert_eq!(files.len(), members.len());
    for (index, (file, (_, data))) in files.iter().zip(members).enumerate() {
        assert_eq!(file.is_solid(), index != 0);
        let payload = file.packed_data(&packed).unwrap();
        assert_eq!(decoder.decode_member(&payload, data.len()).unwrap(), data);
    }
}

#[test]
fn blocks_coded_side_by_side_code_to_the_one_thread_bytes() {
    let data = [
        text(70_000, 16),
        tone(40_000, 2),
        noise(20_000, 17),
        text(60_000, 18),
    ]
    .concat();
    let mut fingerprints = Vec::new();
    for options in levels() {
        let packed = side_by_side(|| {
            encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK).unwrap()
        });
        assert_eq!(decode(&packed, data.len()), data, "{options:?}");
        let one_thread = {
            let _cap = crate::parallel::ThreadCap::set(Some(1));
            encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK).unwrap()
        };
        assert_eq!(one_thread, packed, "{options:?}");
        fingerprints.push((packed.len(), crate::crc32::crc32(&packed)));
    }
    // A solid member runs its blocks on in the fixed table, after a history.
    let (history, member) = data.split_at(50_000);
    let level_three = EncodeOptions::new(16)
        .with_lazy_matching(true)
        .with_lazy_lookahead(2);
    for (options, compact) in [(EncodeOptions::default(), false), (level_three, true)] {
        let options = options.with_max_match_distance(64 * 1024);
        let table = FixedEncodeTable::new(compact);
        let continue_chain = || {
            encode_member_in_blocks(member, history, Some(table), options, false, None, BLOCK)
                .unwrap()
        };
        let continued = {
            let _cap = crate::parallel::ThreadCap::set(Some(1));
            continue_chain()
        };
        #[cfg(all(
            feature = "parallel",
            not(all(target_arch = "wasm32", target_os = "unknown"))
        ))]
        for threads in [2, 8] {
            let many = crate::parallel::private_pool(threads).install(continue_chain);
            assert!(
                many == continued,
                "{threads} threads changed the solid member"
            );
        }
        let mut decoder = Unpack20::new();
        decoder
            .decode_member(
                &encode_member(history, &[], Some(table), options, false, None).unwrap(),
                history.len(),
            )
            .unwrap();
        assert_eq!(
            decoder.decode_member(&continued, member.len()).unwrap(),
            member
        );
        fingerprints.push((continued.len(), crate::crc32::crc32(&continued)));
    }
    // Each block starts from no recent offsets, whatever the thread count.
    assert_eq!(
        fingerprints,
        [
            (55_326, 969_879_645),
            (50_277, 2_194_122_934),
            (48_319, 1_718_131_757),
            (63_269, 1_086_982_408),
            (61_609, 1_804_705_426),
        ]
    );
}

#[test]
fn a_streamed_member_writes_the_same_at_one_thread_and_counts_forward() {
    let data = [text(90_000, 19), tone(30_000, 2), text(40_000, 20)].concat();
    let options = EncodeOptions::default().with_optimal_parse(true);
    let stream = || {
        let (mut out, mut reports) = (Vec::new(), Vec::new());
        let (flow, kept) = encode_streamed(
            &mut &data[..],
            data.len(),
            &[],
            None,
            options,
            true,
            &mut |at| {
                reports.push(at);
                true
            },
            &mut |bytes, at| {
                out.push((bytes.to_vec(), at));
                Ok(ControlFlow::Continue(()))
            },
            BLOCK,
        )
        .unwrap();
        assert!(flow.is_continue());
        // A batch counts its bytes as it commits them, never going back.
        assert!(reports.is_sorted(), "{reports:?}");
        assert_eq!(reports.last(), Some(&data.len()));
        (out, kept)
    };
    let batched = side_by_side(stream);
    let one_thread = {
        let _cap = crate::parallel::ThreadCap::set(Some(1));
        stream()
    };
    assert_eq!(batched, one_thread);
    assert!(
        batched.0.len() > 5,
        "the packed bytes leave a block at a time"
    );
}
