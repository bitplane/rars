use rars::{ArchiveVersion, FeatureSet};

#[test]
fn streaming_directory_sources_cannot_discard_payloads() {
    for (host_os, attributes) in [(3, 0o040750), (2, 0x10)] {
        let entry = rars::rar15_40::StreamingEntry::new(
            b"directory".to_vec(),
            rars::EntrySource::from_bytes(b"must not be discarded".to_vec()),
        )
        .with_host_os(host_os)
        .with_file_attr(attributes);
        let error = rars::rar15_40::write_streaming_archive_to(
            &[entry],
            rars::rar15_40::WriterOptions::new(
                rars::ArchiveVersion::Rar30,
                rars::FeatureSet::store_only(),
            ),
            rars::MemberCoding::Stored,
            None,
            &rars::WriterResources::default(),
            None,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("directory source must be empty"));
    }
}

fn binary_member(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_u32;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        match state % 4 {
            0 if out.len() > 4096 => {
                let from = out.len() - 1 - (state as usize >> 4) % 4096;
                for index in 0..(8 + state as usize % 56) {
                    out.push(out[from + index % (out.len() - from)]);
                }
            }
            1 => out.extend_from_slice(&[0, 0, 0xff, (state >> 8) as u8]),
            _ => out.extend_from_slice(&state.to_le_bytes()),
        }
    }
    out.truncate(len);
    out
}

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}

fn entries(members: &[(&str, &[u8])]) -> Vec<rars::rar15_40::StreamingEntry> {
    members
        .iter()
        .map(|(name, data)| {
            rars::rar15_40::StreamingEntry::new(
                name.as_bytes().to_vec(),
                rars::EntrySource::from_bytes(data.to_vec()),
            )
        })
        .collect()
}

fn rar40() -> rars::rar15_40::WriterOptions {
    rars::rar15_40::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
}

fn in_memory_with(
    entries: &[rars::rar15_40::StreamingEntry],
    options: rars::rar15_40::WriterOptions,
    coding: rars::MemberCoding,
) -> Vec<u8> {
    let mut out = Vec::new();
    rars::rar15_40::write_streaming_archive_to(
        entries,
        options,
        coding,
        None,
        &rars::WriterResources::default(),
        None,
        &mut out,
    )
    .unwrap();
    out
}

fn word_text(len: usize) -> Vec<u8> {
    let words = [
        &b"model"[..],
        b"predicts",
        b"each",
        b"byte",
        b"from",
        b"context",
        b"escape",
        b"window",
        b"archive",
        b"the",
        b"of",
        b"and",
    ];
    let mut state = 0x2545_f491_u32;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(words[(state >> 7) as usize % words.len()]);
        out.push(if state.is_multiple_of(11) {
            b'\n'
        } else {
            b' '
        });
    }
    out.truncate(len);
    out
}

fn named(kind: rars::FilterKind) -> rars::MemberCoding {
    rars::MemberCoding::Filtered(rars::FilterPolicy::explicit(kind))
}

#[test]
fn a_member_that_does_not_shrink_is_stored_whatever_codes_it() {
    use rars::rar15_40::Rar29Method;
    use rars::FilterKind;
    let text = word_text(40_000);
    let noise = noise(20_000);
    let files: [(&str, &[u8]); 3] = [
        ("before.txt", &text),
        ("noise.bin", &noise),
        ("after.txt", &text),
    ];
    let members = entries(&files);
    let expected: Vec<_> = files
        .iter()
        .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
        .collect();
    for solid in [false, true] {
        for method in [Rar29Method::Auto, Rar29Method::Lz, Rar29Method::Ppmd] {
            for coding in [
                rars::MemberCoding::Compressed,
                named(FilterKind::E8E9),
                named(FilterKind::Delta { channels: 4 }),
            ] {
                let mut options = rar40();
                options.features.solid = solid;
                options.method = method;
                let case = format!("solid {solid}, {method:?}, {coding:?}");

                let archive = in_memory_with(&members, options, coding);

                let parsed = rars::rar15_40::Archive::parse(&archive).unwrap();
                let headers: Vec<_> = parsed.files().collect();
                assert_eq!(headers[1].method, 0x30, "{case}");
                assert_eq!(headers[1].pack_size, noise.len() as u64, "{case}");
                // Storing ends a chain, so the member after it starts another.
                assert!(!headers[2].is_solid(), "{case}");
                assert_ne!(headers[2].method, 0x30, "{case}");
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), None),
                    expected,
                    "{case}"
                );
            }
        }
    }
}

fn extracted_set(volumes: &[Vec<u8>], password: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Capture(Rc<RefCell<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let parsed: Vec<_> = volumes
        .iter()
        .map(|volume| rars::rar15_40::Archive::parse_with_password(volume, password).unwrap())
        .collect();
    let mut out = Vec::new();
    rars::rar15_40::extract_volumes_to(
        &parsed,
        match password {
            Some(password) => rars::ArchiveReadOptions::with_password(password),
            None => rars::ArchiveReadOptions::default(),
        },
        |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            out.push((meta.name.clone(), data.clone()));
            Ok(Box::new(Capture(data)))
        },
    )
    .unwrap();
    out.into_iter()
        .map(|(name, data)| (name, data.take()))
        .collect()
}

/// Level 2 used to be a deeper greedy search than level 1, and on runs of
/// zeroes between a repeating phrase it found far matches that displaced
/// the repeat offset and packed larger than level 1 did.
#[test]
fn each_rar29_level_packs_no_larger_than_the_one_below() {
    let mut period = vec![0u8; 4096];
    for _ in 0..91 {
        period.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
    }
    let runs: Vec<u8> = period.iter().copied().cycle().take(160 * 1024).collect();
    let samples = [
        ("binary", binary_member(96 * 1024)),
        ("text", word_text(96 * 1024)),
        ("runs", runs),
    ];
    for (name, data) in samples {
        let members = entries(&[(name, &data)]);
        let mut below = usize::MAX;
        for level in 1..=5u8 {
            let mut options =
                rars::rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());
            options.compression_level = Some(level);
            let archive = in_memory_with(&members, options, rars::MemberCoding::Compressed);
            assert!(
                archive.len() <= below,
                "{name}: level {level} packed {} bytes, the level below {below}",
                archive.len()
            );
            below = archive.len();
        }
    }
}

/// A chain's PPMd member used to move its model's 19 KB of tables through
/// each call by value, and unoptimised that outgrew the 1 MiB main thread
/// Windows gives the CLI, on two lines of text in a solid archive.
#[test]
fn a_solid_ppmd_chain_codes_on_a_1_mib_stack() {
    let text = word_text(48 * 1024);
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let files: [(&str, &[u8]); 2] = [
                ("one.txt", &text[..16 * 1024]),
                ("two.txt", &text[16 * 1024..]),
            ];
            let members = entries(&files);
            let expected: Vec<_> = files
                .iter()
                .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
                .collect();
            for (level, method) in [
                (None, rars::rar15_40::Rar29Method::Auto),
                (Some(5), rars::rar15_40::Rar29Method::Auto),
                (Some(5), rars::rar15_40::Rar29Method::Ppmd),
            ] {
                let mut options = rar40();
                options.features.solid = true;
                options.compression_level = level;
                options.method = method;
                let archive = in_memory_with(&members, options, rars::MemberCoding::Compressed);
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), None),
                    expected,
                    "{level:?} {method:?}"
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
