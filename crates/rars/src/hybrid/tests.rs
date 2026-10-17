use super::*;
use crate::Error;
use std::io::{Read, Seek, SeekFrom};

fn index(cache: u64, disk: u64) -> RepeatIndex {
    RepeatIndex::create(
        std::env::temp_dir(),
        IndexLimits {
            cache_bytes: cache,
            max_disk_bytes: disk,
        },
    )
    .unwrap()
}

fn expected(members: &[(u64, Vec<u8>)], pattern: &[u8]) -> Vec<Occurrence> {
    let mut result = Vec::new();
    for (id, member) in members {
        for offset in 0..=member.len().saturating_sub(pattern.len()) {
            if member.get(offset..offset + pattern.len()) == Some(pattern) {
                result.push(Occurrence {
                    member_id: *id,
                    offset: offset as u64,
                });
            }
        }
    }
    result.sort_unstable();
    result
}

fn binary_strings(maximum: usize) -> Vec<Vec<u8>> {
    (0..=maximum)
        .flat_map(|length| {
            (0..1usize << length).map(move |value| {
                (0..length)
                    .map(|bit| b'a' + ((value >> bit) & 1) as u8)
                    .collect()
            })
        })
        .collect()
}

#[test]
fn exhaustive_suffix_tree_matches_independent_overlapping_oracle() {
    let patterns = binary_strings(5);
    for text in binary_strings(6) {
        // One-byte reads exercise every possible analysis boundary.
        let mut tree = index(2048, 1_000_000);
        tree.begin_member(19).unwrap();
        for chunk in text.chunks(1) {
            tree.append(chunk).unwrap();
        }
        tree.finish_member().unwrap();
        for pattern in patterns.iter().filter(|p| !p.is_empty()) {
            assert_eq!(
                tree.occurrences(pattern).unwrap(),
                expected(&[(19, text.clone())], pattern),
                "text={text:?} pattern={pattern:?}"
            );
        }
        assert!(tree.node_count() <= 2 * (text.len() as u64 + 1) + 1);
    }
}

#[test]
fn generalized_tree_does_not_join_files_and_preserves_overlaps() {
    let texts = [
        b"aaaaa".to_vec(),
        b"banana".to_vec(),
        Vec::new(),
        b"ananas".to_vec(),
        b"aaaaa".to_vec(),
    ];
    let mut tree = index(0, 1_000_000);
    let mut members = Vec::new();
    for (ordinal, text) in texts.into_iter().enumerate() {
        let id = 100 - ordinal as u64;
        tree.begin_member(id).unwrap();
        for chunk in text.chunks(2) {
            tree.append(chunk).unwrap();
        }
        tree.finish_member().unwrap();
        members.push((id, text));
        for pattern in [
            b"a".as_slice(),
            b"aa",
            b"aaa",
            b"ana",
            b"banana",
            b"ananas",
            b"aan",
            b"saaaa",
        ] {
            assert_eq!(
                tree.occurrences(pattern).unwrap(),
                expected(&members, pattern)
            );
        }
    }
    assert_eq!(tree.cache_allocated_bytes(), 0);
}

#[test]
fn every_pair_of_small_files_matches_oracle_in_each_read_geometry() {
    let texts = binary_strings(3);
    for first in &texts {
        for second in &texts {
            let mut tree = index(400, 1_000_000);
            for (id, text) in [(7, first), (3, second)] {
                tree.begin_member(id).unwrap();
                for chunk in text.chunks(2) {
                    tree.append(chunk).unwrap();
                }
                tree.finish_member().unwrap();
            }
            for pattern in texts.iter().filter(|p| !p.is_empty()) {
                assert_eq!(
                    tree.occurrences(pattern).unwrap(),
                    expected(&[(7, first.clone()), (3, second.clone())], pattern),
                    "first={first:?} second={second:?} pattern={pattern:?}"
                );
            }
        }
    }
}

#[test]
fn spilled_index_long_patterns_binary_bytes_and_read_boundaries() {
    let mut data = (0..257).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    data.extend_from_within(..);
    let pattern = data[17..500].to_vec();
    data.extend_from_slice(&pattern);
    let mut tree = index(1024, 2_000_000);
    tree.begin_member(u64::MAX).unwrap();
    for chunk in data.chunks(13) {
        tree.append(chunk).unwrap();
    }
    tree.finish_member().unwrap();
    assert_eq!(
        tree.occurrences(&pattern).unwrap(),
        expected(&[(u64::MAX, data.clone())], &pattern)
    );
    for length in [1, 2, 3, 4, 31, 256, 483] {
        let p = &data[19..19 + length];
        assert_eq!(
            tree.occurrences(p).unwrap(),
            expected(&[(u64::MAX, data.clone())], p)
        );
    }
    assert!(tree.disk_bytes() > tree.cache_allocated_bytes());
    assert!(tree.cache_allocated_bytes() <= 1024);
}

#[test]
fn patterns_are_not_capped_by_codec_match_length_or_read_size() {
    let mut state = 0x1234_5678u32;
    let first = (0..8197)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>();
    let data = [first.as_slice(), first.as_slice()].concat();
    let mut tree = index(64 * 1024, 8 * 1024 * 1024);
    tree.begin_member(0).unwrap();
    for chunk in data.chunks(17) {
        tree.append(chunk).unwrap();
    }
    tree.finish_member().unwrap();
    let pattern = &first[103..7104];
    assert_eq!(
        tree.occurrences(pattern).unwrap(),
        [
            Occurrence {
                member_id: 0,
                offset: 103
            },
            Occurrence {
                member_id: 0,
                offset: 8300
            }
        ]
    );
    assert_eq!(tree.read_member_range(0, 0, data.len()).unwrap(), data);
}

#[test]
fn cancellation_precedes_admission_and_mid_extension_never_exposes_partial_tree() {
    use std::cell::Cell;
    let mut tree = index(0, 88 + 40);
    tree.begin_member(0).unwrap();
    assert_eq!(
        tree.append_with_cancellation(b"would exceed disk", &|| true)
            .unwrap_err(),
        Error::Cancelled
    );
    // A cancellation before mutation leaves the operation retryable.
    tree.finish_member().unwrap_err(); // An empty suffix itself needs a node.
    let mut tree = index(1024, 1_000_000);
    tree.begin_member(0).unwrap();
    let calls = Cell::new(0);
    let cancelled = || {
        calls.set(calls.get() + 1);
        calls.get() > 5
    };
    assert_eq!(
        tree.append_with_cancellation(b"abababababababab", &cancelled)
            .unwrap_err(),
        Error::Cancelled
    );
    assert!(matches!(tree.finish_member(), Err(Error::WriterFailure(_))));
    assert!(matches!(
        tree.occurrences(b"ab"),
        Err(Error::WriterFailure(_))
    ));
}

#[test]
fn disk_limits_cover_member_raw_node_and_split_growth_exactly() {
    let data = b"mississippi";
    let mut complete = index(0, 100_000);
    complete.begin_member(0).unwrap();
    complete.append(data).unwrap();
    complete.finish_member().unwrap();
    let required = complete.disk_bytes();
    for limit in [87, 88, 127, 128, 129, 215, 216, required - 1, required] {
        let result = RepeatIndex::create(
            std::env::temp_dir(),
            IndexLimits {
                cache_bytes: 0,
                max_disk_bytes: limit,
            },
        );
        let result = result.and_then(|mut tree| {
            tree.begin_member(0)?;
            tree.append(data)?;
            tree.finish_member()?;
            assert_eq!(tree.disk_bytes(), required);
            assert_eq!(
                tree.occurrences(b"issi")?,
                expected(&[(0, data.to_vec())], b"issi")
            );
            Ok(())
        });
        if limit < required {
            assert!(
                matches!(result, Err(Error::WriterSpoolLimitExceeded { .. })),
                "limit={limit}: {result:?}"
            );
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn bounded_occurrences_report_truncation_without_truncating_the_index() {
    let mut tree = index(1024, 1_000_000);
    tree.begin_member(1).unwrap();
    tree.append(b"aaaa").unwrap();
    tree.finish_member().unwrap();
    assert_eq!(tree.occurrences_limited(b"aa", 2).unwrap().0.len(), 2);
    assert!(tree.occurrences_limited(b"aa", 2).unwrap().1);
    assert!(!tree.occurrences_limited(b"aa", 3).unwrap().1);
    assert_eq!(
        tree.occurrences_limited(b"aa", 0).unwrap(),
        (Vec::new(), true)
    );
    assert_eq!(
        tree.occurrences_limited(b"z", 0).unwrap(),
        (Vec::new(), false)
    );
    let mut visited = 0;
    assert_eq!(
        tree.for_each_occurrence(b"aa", |_| {
            visited += 1;
            Ok(())
        })
        .unwrap(),
        3
    );
    assert_eq!(visited, 3);
    assert_eq!(
        tree.for_each_occurrence(b"a", |_| Err(Error::Cancelled))
            .unwrap_err(),
        Error::Cancelled
    );
    assert_eq!(tree.occurrences(b"a").unwrap().len(), 4);
}

#[test]
fn exact_disk_refusal_poisoning_and_no_truncated_success() {
    assert!(matches!(
        RepeatIndex::create(
            std::env::temp_dir(),
            IndexLimits {
                cache_bytes: 0,
                max_disk_bytes: 87
            }
        ),
        Err(Error::WriterSpoolLimitExceeded {
            required: 88,
            used: 0,
            ..
        })
    ));
    let mut tree = index(0, 88 + 40 + 1);
    tree.begin_member(2).unwrap();
    assert!(matches!(
        tree.append(b"x"),
        Err(Error::WriterSpoolLimitExceeded { .. })
    ));
    assert!(matches!(
        tree.occurrences(b"x"),
        Err(Error::WriterFailure(_))
    ));
    assert!(matches!(tree.finish_member(), Err(Error::WriterFailure(_))));
}

#[test]
fn capture_sources_outlive_index_are_range_isolated_and_seekable() {
    let mut tree = index(8192, 1_000_000);
    let directory = tree.test_directory().to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["nodes", "members", "captured"] {
            assert_eq!(
                std::fs::metadata(directory.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    for (id, data) in [(31, b"first".as_slice()), (9, b"second"), (8, b"")] {
        tree.begin_member(id).unwrap();
        tree.append(data).unwrap();
        tree.finish_member().unwrap();
    }
    assert_eq!(tree.read_member_range(9, 1, 4).unwrap(), b"econ");
    assert!(tree.read_member_range(9, 4, 3).is_err());
    let first = tree.member_source(31).unwrap();
    let second = tree.member_source(9).unwrap();
    drop(tree);
    for (source, expected) in [(first, b"first".as_slice()), (second, b"second")] {
        let mut reader = source.open().unwrap();
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, expected);
        reader.seek(SeekFrom::End(-2)).unwrap();
        result.clear();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, expected[expected.len() - 2..]);
        assert!(reader.seek(SeekFrom::Start(u64::MAX)).is_err());
    }
    assert!(!directory.exists());
}

#[test]
fn refused_construction_leaves_no_half_directory_or_private_payload() {
    let directory = crate::scratch::case("hybrid-refused-construction");
    assert!(RepeatIndex::create(
        &*directory,
        IndexLimits {
            cache_bytes: 0,
            max_disk_bytes: 0
        }
    )
    .is_err());
    assert_eq!(std::fs::read_dir(&*directory).unwrap().count(), 0);
}

#[test]
fn index_state_errors_and_unique_empty_member_terminators() {
    let mut tree = index(1024, 1_000_000);
    assert!(tree.append(b"x").is_err());
    assert!(tree.finish_member().is_err());
    assert!(tree.occurrences(b"").is_err());
    tree.begin_member(0).unwrap();
    assert!(tree.begin_member(1).is_err());
    assert!(tree.occurrences(b"x").is_err());
    assert!(tree.member_source(0).is_err());
    tree.finish_member().unwrap();
    assert_eq!(tree.begin_member(0).unwrap_err(), Error::DuplicateEntry);
    for id in 1..20 {
        tree.begin_member(id).unwrap();
        tree.finish_member().unwrap();
    }
    assert_eq!(tree.member_count(), 20);
    assert!(tree.occurrences(b"x").unwrap().is_empty());
}

#[test]
fn profiles_shortlist_and_exact_minimax_are_deterministic() {
    let desktop = HybridOptions::new(HybridProfile::Desktop);
    assert_eq!(desktop.variant(), 63);
    assert!(!desktop.archive_analysis() && !desktop.member_order_optimization());
    assert_eq!(desktop.memory_bytes(), 256 * 1024 * 1024);
    assert_eq!(
        HybridOptions::new(HybridProfile::Server).candidate_states(),
        8
    );
    assert!(desktop.with_variant(64).is_err());
    let mut stats = DictionaryStats::default();
    stats.observe(256 * 1024, 95);
    stats.observe(1024 * 1024, 5);
    assert_eq!(
        dictionary_shortlist(&stats, 512 * 1024, 4 * 1024 * 1024, 2).unwrap(),
        [256 * 1024, 512 * 1024]
    );
    assert_eq!(
        dictionary_shortlist(&stats, 512 * 1024, 4 * 1024 * 1024, 3).unwrap(),
        [256 * 1024, 512 * 1024, 4 * 1024 * 1024]
    );
    let a = DictionaryMeasurement {
        dictionary_size: 128 * 1024,
        packed_bytes: 200,
        work_units: 100,
        memory_bytes: 100,
    };
    let b = DictionaryMeasurement {
        dictionary_size: 256 * 1024,
        packed_bytes: 100,
        work_units: 200,
        memory_bytes: 100,
    };
    assert_eq!(choose_minimax(&[b, a]).unwrap(), a); // Equal worst ratio: smaller dictionary.
    assert_eq!(choose_minimax(&[a, b]).unwrap(), a);
    assert!(choose_minimax(&[]).is_err());
    // Oversized witnesses must not masquerade as reachable 4GiB repeats.
    let mut far = DictionaryStats::default();
    far.observe((1u64 << 40) + 1, u64::MAX);
    assert_eq!(far.distance_bytes[41], u64::MAX);
    assert_eq!(
        dictionary_shortlist(&far, 512 * 1024, 4 * 1024 * 1024, 2).unwrap(),
        [128 * 1024, 512 * 1024]
    );
    let fractional = 192 * 1024;
    assert_eq!(
        dictionary_shortlist(&stats, fractional, fractional, 3).unwrap(),
        [128 * 1024, fractional]
    );
}
