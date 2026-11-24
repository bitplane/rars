#![cfg(feature = "write")]

use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ExtractionDecision as Decision, ExtractionOutcome as Outcome,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{cell::RefCell, io, io::Write, rc::Rc};

const VERSIONS: [ArchiveVersion; 8] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
    ArchiveVersion::Rar70,
];

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn archive(version: ArchiveVersion, solid: bool, encrypted: bool) -> Archive {
    let mut builder = Builder::new(version)
        .solid(solid)
        .password(encrypted.then(|| b"secret".to_vec()));
    for (name, len) in [(b"first".as_slice(), 4096), (b"second", 32), (b"third", 64)] {
        builder
            .add_bytes(name.to_vec(), vec![42; len], None, None)
            .unwrap();
    }
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

#[test]
fn skip_precedes_limits_and_stop_precedes_later_members() {
    for version in VERSIONS {
        let archive = archive(version, false, false);
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut visited = Vec::new();
        let outcome = archive
            .extract_with_control(
                ArchiveReadOptions::new()
                    .with_max_member_output_bytes(32)
                    .with_max_total_output_bytes(32),
                |member| {
                    visited.push(member.meta.name.clone());
                    Ok(match member.meta.name.as_slice() {
                        b"first" => {
                            assert_eq!(member.meta.unpacked_size, 4096);
                            Decision::Skip
                        }
                        b"second" => Decision::Extract(Box::new(Capture(output.clone()))),
                        _ => Decision::Stop,
                    })
                },
            )
            .unwrap();
        assert_eq!(outcome, Outcome::Stopped);
        assert_eq!(*output.borrow(), vec![42; 32]);
        assert_eq!(
            visited,
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        let mut calls = 0;
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| {
                    calls += 1;
                    Ok(Decision::Stop)
                })
                .unwrap(),
            Outcome::Stopped
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn member_handler_can_continue_after_a_member_output_limit() {
    for version in VERSIONS {
        let archive = archive(version, false, false);

        let error = archive
            .extract_with_control(
                ArchiveReadOptions::new().with_max_member_output_bytes(64),
                |_| Ok(Decision::Extract(Box::new(io::sink()))),
            )
            .unwrap_err();
        assert!(
            matches!(
                error.root_cause(),
                Error::MemberOutputLimitExceeded {
                    limit: 64,
                    required: 4096
                }
            ),
            "{version:?}: {error}"
        );

        let explicit_calls = AtomicUsize::new(0);
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new().with_max_member_output_bytes(64),
                |_| Ok(Decision::Extract(Box::new(io::sink()))),
                |_, _| {
                    explicit_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(rars::ExtractionErrorAction::Continue)
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
        assert_eq!(explicit_calls.load(Ordering::Relaxed), 0);

        let handler_calls = AtomicUsize::new(0);
        let handler = |member: &rars::ArchiveMember, error: &Error| {
            assert_eq!(member.meta.name, b"first");
            assert!(matches!(
                error.root_cause(),
                Error::MemberOutputLimitExceeded {
                    limit: 64,
                    required: 4096
                }
            ));
            handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let output = Rc::new(RefCell::new(Vec::new()));
        let outcome = archive
            .extract_with_control(
                ArchiveReadOptions::new()
                    .with_max_member_output_bytes(64)
                    .with_member_error_handler(&handler),
                |_| Ok(Decision::Extract(Box::new(Capture(output.clone())))),
            )
            .unwrap();
        assert_eq!(outcome, Outcome::Complete);
        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*output.borrow(), vec![42; 96]);
    }
}

#[test]
fn volume_api_member_handler_can_continue_after_a_member_output_limit() {
    for version in [ArchiveVersion::Rar14, ArchiveVersion::Rar50] {
        let archive = archive(version, false, false);
        let handler_calls = AtomicUsize::new(0);
        let handler = |member: &rars::ArchiveMember, error: &Error| {
            assert_eq!(member.meta.name, b"first");
            assert!(matches!(
                error.root_cause(),
                Error::MemberOutputLimitExceeded {
                    limit: 64,
                    required: 4096
                }
            ));
            handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let output = Rc::new(RefCell::new(Vec::new()));
        rars::extract_volumes_to_with_options(
            std::slice::from_ref(&archive),
            ArchiveReadOptions::new()
                .with_max_member_output_bytes(64)
                .with_member_error_handler(&handler),
            |_| Ok(Box::new(Capture(output.clone()))),
        )
        .unwrap();
        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*output.borrow(), vec![42; 96]);
    }
}

#[test]
fn volume_api_member_handler_can_continue_after_a_dictionary_limit() {
    let archive = archive(ArchiveVersion::Rar50, false, false);
    let failed = std::sync::Mutex::new(Vec::new());
    let handler = |member: &rars::ArchiveMember, error: &Error| {
        assert!(matches!(
            error.root_cause(),
            Error::Rar50DictionaryLimitExceeded { limit: 0, .. }
        ));
        failed.lock().unwrap().push(member.meta.name.clone());
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let mut opened = 0;
    rars::extract_volumes_to_with_options(
        std::slice::from_ref(&archive),
        ArchiveReadOptions::new()
            .with_rar50_dictionary_size_limit(0)
            .with_member_error_handler(&handler),
        |_| {
            opened += 1;
            Ok(Box::new(io::sink()))
        },
    )
    .unwrap();
    assert_eq!(
        *failed.lock().unwrap(),
        [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert_eq!(opened, 0);
}

#[test]
fn volume_api_split_member_limits_remain_terminal() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .volume_size(Some(512));
    builder
        .add_bytes(b"split".to_vec(), vec![42; 4096], None, None)
        .unwrap();
    let volumes: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 1);

    let handler_calls = AtomicUsize::new(0);
    let handler = |_: &rars::ArchiveMember, _: &Error| {
        handler_calls.fetch_add(1, Ordering::Relaxed);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let error = rars::extract_volumes_to_with_options(
        &volumes,
        ArchiveReadOptions::new()
            .with_max_member_output_bytes(64)
            .with_member_error_handler(&handler),
        |_| Ok(Box::new(io::sink())),
    )
    .unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::MemberOutputLimitExceeded {
            limit: 64,
            required: 4096
        }
    ));
    assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
}

/// `first`, then `split` across several volumes, then `after`, with the
/// packed data in the second volume damaged.
fn damaged_split_set(version: ArchiveVersion, solid: bool, store: bool) -> Vec<Archive> {
    let mut builder = Builder::new(version)
        .solid(solid)
        .store(store)
        .volume_size(Some(4096));
    for (seed, (name, len)) in (1..).zip([("first", 100), ("split", 100_000), ("after", 300)]) {
        builder
            .add_bytes(name.as_bytes().to_vec(), noisy_text(seed, len), None, None)
            .unwrap();
    }
    let mut volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() >= 3, "{version:?}");
    let at = volumes[1].len() / 2;
    volumes[1][at] ^= 0xff;
    volumes
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect()
}

fn in_volume(error: &Error) -> Option<usize> {
    match error {
        Error::InVolume { index, .. } => Some(*index),
        Error::AtEntry { source, .. } | Error::AtArchiveOffset { source, .. } => in_volume(source),
        _ => None,
    }
}

/// Members written by an extraction, by name.
type Written = Rc<RefCell<Vec<(Vec<u8>, Rc<RefCell<Vec<u8>>>)>>>;

fn extract_set(
    volumes: &[Archive],
    options: ArchiveReadOptions<'_>,
) -> (rars::Result<()>, Written) {
    let written = Written::default();
    let result = rars::extract_volumes_to_with_options(volumes, options, |meta| {
        let output = Rc::new(RefCell::new(Vec::new()));
        written
            .borrow_mut()
            .push((meta.name.clone(), Rc::clone(&output)));
        Ok(Box::new(Capture(output)))
    });
    (result, written)
}

#[test]
fn volume_api_member_handler_goes_past_a_damaged_split_member() {
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for (solid, store) in [(false, false), (true, false), (false, true)] {
            let case = format!("{version:?}, solid {solid}, stored {store}");
            let volumes = damaged_split_set(version, solid, store);

            let failed = std::sync::Mutex::new(Vec::new());
            let handler = |member: &rars::ArchiveMember, error: &Error| {
                failed
                    .lock()
                    .unwrap()
                    .push((member.meta.name.clone(), error.clone()));
                Ok(rars::ExtractionErrorAction::Continue)
            };
            let (result, written) = extract_set(
                &volumes,
                ArchiveReadOptions::new().with_member_error_handler(&handler),
            );
            result.unwrap_or_else(|error| panic!("{case}: {error}"));
            let failed = failed.into_inner().unwrap();
            assert_eq!(failed[0].0, b"split", "{case}");
            // The volume whose packed data fails its own CRC32 is named.
            assert_eq!(in_volume(&failed[0].1), Some(1), "{case}: {}", failed[0].1);
            let written = written.borrow();
            let names: Vec<_> = written.iter().map(|(name, _)| name.as_slice()).collect();
            assert_eq!(names, [&b"first"[..], b"split", b"after"], "{case}");
            assert_eq!(*written[0].1.borrow(), noisy_text(1, 100), "{case}");
            if solid {
                // It decodes from the state the failed member left, as unrar does.
                assert!(failed.len() <= 2, "{case}");
            } else {
                assert_eq!(failed.len(), 1, "{case}");
                assert_eq!(*written[2].1.borrow(), noisy_text(3, 300), "{case}");
            }

            // Without a handler, the run ends at the split member.
            let (result, written) = extract_set(&volumes, ArchiveReadOptions::new());
            assert!(result.is_err(), "{case}");
            assert_eq!(written.borrow().len(), 2, "{case}");
        }
    }
}

#[test]
fn volume_api_a_missing_volume_still_ends_the_run() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let mut volumes = damaged_split_set(version, false, false);
        // The set's last volume holds the end of `split` and all of `after`.
        volumes.pop();
        let handler_calls = AtomicUsize::new(0);
        let handler = |_: &rars::ArchiveMember, _: &Error| {
            handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let (result, written) = extract_set(
            &volumes,
            ArchiveReadOptions::new().with_member_error_handler(&handler),
        );
        assert!(result.is_err(), "{version:?}");
        assert_eq!(handler_calls.load(Ordering::Relaxed), 0, "{version:?}");
        assert_eq!(written.borrow().len(), 2, "{version:?}");
    }
}

/// A RAR 1.4 archive's bytes after its main header: its members.
fn rar14_members(bytes: &[u8]) -> &[u8] {
    &bytes[usize::from(u16::from_le_bytes([bytes[4], bytes[5]]))..]
}

/// [`damaged_split_set`] for RAR 1.4. rars writes a RAR 1.4 volume set of
/// one file, so `first` and `after` are spliced in from archives of their
/// own. A solid set leaves `first` out, since `split` is compressed as the
/// first member of its stream.
fn damaged_rar14_split_set(solid: bool, store: bool) -> Vec<Vec<u8>> {
    let member = |name: &str, seed, len| {
        let mut builder = Builder::new(ArchiveVersion::Rar14).store(store);
        builder
            .add_bytes(name.as_bytes().to_vec(), noisy_text(seed, len), None, None)
            .unwrap();
        rar14_members(&builder.to_bytes().unwrap()).to_vec()
    };
    let mut builder = Builder::new(ArchiveVersion::Rar14)
        .solid(solid)
        .store(store)
        .volume_size(Some(4096));
    builder
        .add_bytes(b"split".to_vec(), noisy_text(2, 100_000), None, None)
        .unwrap();
    let mut volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() >= 3);
    if !solid {
        let at = volumes[0].len() - rar14_members(&volumes[0]).len();
        volumes[0].splice(at..at, member("first", 1, 100));
    }
    volumes.last_mut().unwrap().extend(member("after", 3, 300));
    let at = volumes[1].len() / 2;
    volumes[1][at] ^= 0xff;
    volumes
}

fn read_set(volumes: Vec<Vec<u8>>) -> Vec<Archive> {
    volumes
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect()
}

/// Issue #601: as for RAR 1.5 and later, a member error handler goes past
/// a RAR 1.4 member split across volumes. Its fragments carry no checksum
/// of their own packed data, so no volume is named.
#[test]
fn volume_api_member_handler_goes_past_a_damaged_rar14_split_member() {
    for (solid, store) in [(false, false), (true, false), (false, true)] {
        let case = format!("solid {solid}, stored {store}");
        let volumes = read_set(damaged_rar14_split_set(solid, store));

        let failed = std::sync::Mutex::new(Vec::new());
        let handler = |member: &rars::ArchiveMember, error: &Error| {
            failed
                .lock()
                .unwrap()
                .push((member.meta.name.clone(), error.clone()));
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let (result, written) = extract_set(
            &volumes,
            ArchiveReadOptions::new().with_member_error_handler(&handler),
        );
        result.unwrap_or_else(|error| panic!("{case}: {error}"));
        let failed = failed.into_inner().unwrap();
        assert_eq!(failed[0].0, b"split", "{case}");
        assert_eq!(in_volume(&failed[0].1), None, "{case}: {}", failed[0].1);
        let written = written.borrow();
        let names: Vec<_> = written.iter().map(|(name, _)| name.as_slice()).collect();
        if solid {
            assert_eq!(names, [&b"split"[..], b"after"], "{case}");
            assert!(failed.len() <= 2, "{case}");
        } else {
            assert_eq!(names, [&b"first"[..], b"split", b"after"], "{case}");
            assert_eq!(failed.len(), 1, "{case}");
            assert_eq!(*written[0].1.borrow(), noisy_text(1, 100), "{case}");
            assert_eq!(*written[2].1.borrow(), noisy_text(3, 300), "{case}");
        }

        // Without a handler, the run ends at the split member.
        let (result, written) = extract_set(&volumes, ArchiveReadOptions::new());
        assert!(result.is_err(), "{case}");
        assert_eq!(written.borrow().len(), names.len() - 1, "{case}");
    }
}

/// Issue #601: a RAR 1.4 set missing the volume that holds a split member's
/// end still ends the run without asking the handler.
#[test]
fn volume_api_a_missing_rar14_volume_still_ends_the_run() {
    let mut volumes = damaged_rar14_split_set(false, false);
    volumes.pop();
    let volumes = read_set(volumes);
    let handler_calls = AtomicUsize::new(0);
    let handler = |_: &rars::ArchiveMember, _: &Error| {
        handler_calls.fetch_add(1, Ordering::Relaxed);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let (result, written) = extract_set(
        &volumes,
        ArchiveReadOptions::new().with_member_error_handler(&handler),
    );
    assert!(result.is_err());
    assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
    assert_eq!(written.borrow().len(), 2);
}

#[test]
fn operation_wide_and_solid_member_limits_remain_terminal() {
    let handler_calls = AtomicUsize::new(0);
    let handler = |_: &rars::ArchiveMember, _: &Error| {
        handler_calls.fetch_add(1, Ordering::Relaxed);
        Ok(rars::ExtractionErrorAction::Continue)
    };

    let independent = archive(ArchiveVersion::Rar50, false, false);
    let error = independent
        .extract_with_control(
            ArchiveReadOptions::new()
                .with_max_total_output_bytes(64)
                .with_member_error_handler(&handler),
            |_| Ok(Decision::Extract(Box::new(io::sink()))),
        )
        .unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::TotalOutputLimitExceeded { .. }
    ));
    assert_eq!(handler_calls.load(Ordering::Relaxed), 0);

    let solid_archive = archive(ArchiveVersion::Rar50, true, false);
    let error = solid_archive
        .extract_with_control(
            ArchiveReadOptions::new()
                .with_max_member_output_bytes(64)
                .with_member_error_handler(&handler),
            |_| Ok(Decision::Extract(Box::new(io::sink()))),
        )
        .unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::MemberOutputLimitExceeded { .. }
    ));
    assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
}

#[test]
#[cfg(feature = "parallel")]
fn parallel_member_handler_can_continue_after_a_member_output_limit() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let archive = archive(version, false, false);
        let handler_calls = AtomicUsize::new(0);
        let handler = |member: &rars::ArchiveMember, error: &Error| {
            assert_eq!(member.meta.name, b"first");
            assert!(matches!(
                error.root_cause(),
                Error::MemberOutputLimitExceeded { .. }
            ));
            handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let mut opened = Vec::new();
        archive
            .extract_to_parallel_buffered_with_options(
                ArchiveReadOptions::new()
                    .with_threads(2)
                    .with_max_member_output_bytes(64)
                    .with_member_error_handler(&handler),
                |member| {
                    opened.push(member.name.clone());
                    Ok(Box::new(io::sink()))
                },
            )
            .unwrap();
        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert_eq!(opened, [b"second".to_vec(), b"third".to_vec()]);

        let terminal_handler_calls = AtomicUsize::new(0);
        let terminal_handler = |_: &rars::ArchiveMember, _: &Error| {
            terminal_handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let error = archive
            .extract_to_parallel_buffered_with_options(
                ArchiveReadOptions::new()
                    .with_threads(2)
                    .with_max_total_output_bytes(64)
                    .with_member_error_handler(&terminal_handler),
                |_| Ok(Box::new(io::sink())),
            )
            .unwrap_err();
        assert!(matches!(
            error.root_cause(),
            Error::TotalOutputLimitExceeded { .. }
        ));
        assert_eq!(terminal_handler_calls.load(Ordering::Relaxed), 0);
    }
}

/// Compressible text with a byte of noise in every seven.
fn noisy_text(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            if i % 7 == 0 {
                x as u8
            } else {
                b"the quick brown fox "[i % 20]
            }
        })
        .collect()
}

fn noisy_archive(version: ArchiveVersion, members: &[(&str, usize)]) -> Archive {
    let mut builder = Builder::new(version);
    for (seed, (name, len)) in (1..).zip(members) {
        builder
            .add_bytes(name.as_bytes().to_vec(), noisy_text(seed, *len), None, None)
            .unwrap();
    }
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

/// Extracts under a reader workspace limit, with a handler that carries on if
/// `carry_on`, and returns whether the call succeeded, the members the handler
/// passed over and the members extracted. Streaming opens a member's writer
/// before it can be refused, so an opened member counts only if it passed.
fn extract_under_workspace_limit(
    archive: &Archive,
    limit: u64,
    carry_on: bool,
    parallel: bool,
) -> (bool, Vec<String>, Vec<String>) {
    let failed = std::sync::Mutex::new(Vec::new());
    let handler = |member: &rars::ArchiveMember, error: &Error| {
        assert!(
            matches!(
                error.root_cause(),
                Error::Codec(rars::codec::Error::WorkspaceLimitExceeded(_))
            ),
            "{error}"
        );
        let name = String::from_utf8_lossy(&member.meta.name).into_owned();
        failed.lock().unwrap().push(name);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let mut options = ArchiveReadOptions::new().with_max_reader_workspace_bytes(limit);
    if carry_on {
        options = options.with_member_error_handler(&handler);
    }
    let mut written = Vec::new();
    let open = |meta: &rars::ExtractedEntryMeta| -> rars::Result<Box<dyn Write>> {
        written.push(String::from_utf8_lossy(&meta.name).into_owned());
        Ok(Box::new(io::sink()))
    };
    let result = if parallel {
        #[cfg(feature = "parallel")]
        {
            archive.extract_to_parallel_buffered_with_options(options.with_threads(4), open)
        }
        #[cfg(not(feature = "parallel"))]
        unreachable!()
    } else {
        archive.extract_to_with_options(options, open)
    };
    let failed = failed.into_inner().unwrap();
    written.retain(|name| !failed.contains(name));
    (result.is_ok(), failed, written)
}

#[test]
fn a_workspace_refusal_passes_over_only_that_member() {
    let modes: &[bool] = if cfg!(feature = "parallel") {
        &[false, true]
    } else {
        &[false]
    };
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let archive = noisy_archive(version, &[("a", 1024), ("big", 1 << 20), ("c", 1024)]);
        for &parallel in modes {
            let (ok, failed, written) =
                extract_under_workspace_limit(&archive, 256 << 10, true, parallel);
            assert!(ok, "{version:?} parallel={parallel}");
            assert_eq!(failed, ["big"], "{version:?} parallel={parallel}");
            assert_eq!(written, ["a", "c"], "{version:?} parallel={parallel}");
        }
    }
}

/// A worker decodes within a share of the workspace. A member refused there is
/// streamed again with all of it, so parallel extraction admits and refuses
/// the same members as sequential extraction under the same limit.
#[test]
#[cfg(feature = "parallel")]
fn parallel_extraction_under_a_workspace_limit_matches_sequential() {
    let members = [
        ("m0", 256 << 10),
        ("m1", 256 << 10),
        ("m2", 256 << 10),
        ("m3", 256 << 10),
    ];
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let archive = noisy_archive(version, &members);
        for limit in [256 << 10, 768 << 10, 2560 << 10, 6 << 20, 20 << 20] {
            for carry_on in [false, true] {
                assert_eq!(
                    extract_under_workspace_limit(&archive, limit, carry_on, true),
                    extract_under_workspace_limit(&archive, limit, carry_on, false),
                    "{version:?} limit={limit} carry_on={carry_on}"
                );
            }
        }
    }
}

#[test]
#[cfg(feature = "encryption")]
fn encrypted_members_can_be_skipped_without_a_password() {
    for version in VERSIONS.into_iter().filter(|v| *v != ArchiveVersion::Rar14) {
        let archive = archive(version, false, true);
        let mut calls = 0;
        let outcome = archive
            .extract_with_control(ArchiveReadOptions::new(), |member| {
                assert!(member.meta.is_encrypted);
                calls += 1;
                Ok(Decision::Skip)
            })
            .unwrap();
        assert_eq!(outcome, Outcome::Complete);
        assert_eq!(calls, 3);
    }
}

#[test]
fn solid_skipping_is_refused_but_discarding_preserves_history_and_accounting() {
    for version in VERSIONS {
        let archive = archive(version, true, false);
        let error = archive
            .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Skip))
            .unwrap_err();
        assert!(matches!(error.root_cause(), Error::CannotSkipSolidMember));
        assert_eq!(error.entry_context().unwrap().0, b"first");
        let output = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |member| {
                    Ok(Decision::Extract(if member.meta.name == b"first" {
                        Box::new(io::sink()) as Box<dyn Write>
                    } else {
                        Box::new(Capture(output.clone()))
                    }))
                })
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(*output.borrow(), vec![42; 96]);
        let error = archive
            .extract_with_control(
                ArchiveReadOptions::new().with_max_total_output_bytes(4096),
                |_| Ok(Decision::Extract(Box::new(io::sink()))),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
        assert_eq!(error.entry_context().unwrap().0, b"second");
    }
}

#[test]
fn callback_cancellation_and_errors_do_not_become_successful_stops() {
    let archive = archive(ArchiveVersion::Rar50, false, false);
    let token = rars::ReadCancellation::new();
    let member_error_calls = AtomicUsize::new(0);
    let member_error_handler = |_: &rars::ArchiveMember, _: &Error| {
        member_error_calls.fetch_add(1, Ordering::Relaxed);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let error = archive
        .extract_with_control(
            ArchiveReadOptions::new()
                .with_cancellation(&token)
                .with_member_error_handler(&member_error_handler),
            |_| {
                token.cancel();
                Ok(Decision::Stop)
            },
        )
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Cancelled);
    assert_eq!(member_error_calls.load(Ordering::Relaxed), 0);
    let mut calls = 0;
    let error = archive
        .extract_with_control(ArchiveReadOptions::new(), |_| {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into())
        })
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert_eq!(calls, 1);
}

#[test]
fn skipping_a_bad_checksum_continues_but_extracting_it_stops() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut archive = archive(version, false, false);
        match &mut archive {
            Archive::Rar13(a) => a.entries[0].header.file_crc ^= 1,
            Archive::Rar15To40(a) => {
                for block in &mut a.blocks {
                    if let rars::rar15_40::Block::File(file) = block {
                        if file.name == b"first" {
                            file.file_crc ^= 1;
                        }
                    }
                }
            }
            Archive::Rar50Plus(a) => {
                for block in &mut a.blocks {
                    if let rars::rar50::Block::File(file) = block {
                        if file.name == b"first" {
                            file.hash = None;
                            file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        let token = rars::ReadCancellation::new();
        let mut selected = 0;
        let mut failures = 0;
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new().with_cancellation(&token),
                |_| {
                    selected += 1;
                    Ok(Decision::Extract(Box::new(io::sink())))
                },
                |_, error| {
                    assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
                    failures += 1;
                    token.cancel();
                    Ok(rars::ExtractionErrorAction::Continue)
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::Cancelled);
        assert_eq!((selected, failures), (1, 1));
        let mut selected = 0;
        let mut failures = 0;
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new(),
                |_| {
                    selected += 1;
                    Ok(Decision::Extract(Box::new(io::sink())))
                },
                |member, error| {
                    assert_eq!(member.meta.name, b"first");
                    assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
                    failures += 1;
                    Ok(rars::ExtractionErrorAction::Abort)
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
        assert_eq!(error.entry_context().unwrap().0, b"first");
        assert_eq!((selected, failures), (1, 1));
        let output = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |member| {
                    Ok(if member.meta.name == b"first" {
                        Decision::Skip
                    } else {
                        Decision::Extract(Box::new(Capture(output.clone())))
                    })
                })
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(*output.borrow(), vec![42; 96]);
        let mut calls = 0;
        let error = archive
            .extract_with_control(ArchiveReadOptions::new(), |_| {
                calls += 1;
                Ok(Decision::Extract(Box::new(io::sink())))
            })
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
        assert_eq!(calls, 1);

        for limit in [4096, 4192] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let mut failures = 0;
            let result = archive.extract_with_control_and_errors(
                ArchiveReadOptions::new()
                    .with_max_total_output_bytes(limit)
                    .with_rar50_buffered_decode_limit(0),
                |member| {
                    Ok(Decision::Extract(if member.meta.name == b"first" {
                        Box::new(io::sink()) as Box<dyn Write>
                    } else {
                        Box::new(Capture(output.clone()))
                    }))
                },
                |member, error| {
                    assert_eq!(member.meta.name, b"first");
                    assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
                    failures += 1;
                    Ok(rars::ExtractionErrorAction::Continue)
                },
            );
            assert_eq!(failures, 1);
            if limit == 4096 {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
                assert_eq!(error.entry_context().unwrap().0, b"second");
                assert!(output.borrow().is_empty());
            } else {
                assert_eq!(result.unwrap(), Outcome::Complete);
                assert_eq!(*output.borrow(), vec![42; 96]);
            }
        }
    }
}

#[test]
fn solid_failures_and_callback_errors_cannot_be_continued() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for version in VERSIONS {
        let archive = archive(version, true, false);
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new(),
                |_| Ok(Decision::Extract(Box::new(Broken))),
                |_, _| panic!("solid failure must not offer recovery"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::Io);
    }
    let archive = archive(ArchiveVersion::Rar50, false, false);
    let error = archive
        .extract_with_control_and_errors(
            ArchiveReadOptions::new(),
            |_| Err(io::Error::other("callback failed").into()),
            |_, _| panic!("decision callback errors are fatal"),
        )
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
}

#[test]
fn split_members_never_offer_independent_error_recovery() {
    // These flags are exposed in the parsed archive model. A split payload
    // requires the multivolume reader, even if an error callback asks to continue.
    for flags in [0x0001, 0x0002, 0x0003] {
        let mut archive = archive(ArchiveVersion::Rar29, false, false);
        let Archive::Rar15To40(legacy) = &mut archive else {
            unreachable!()
        };
        let file = legacy
            .blocks
            .iter_mut()
            .find_map(|block| match block {
                rars::rar15_40::Block::File(file) => Some(file),
                _ => None,
            })
            .unwrap();
        file.block.flags |= flags;
        let mut selected = 0;
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new(),
                |_| {
                    selected += 1;
                    Ok(Decision::Extract(Box::new(io::sink())))
                },
                |_, _| panic!("split payloads cannot be recovered independently"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::InvalidArchive);
        assert_eq!(selected, 1);

        let handler_calls = AtomicUsize::new(0);
        let handler = |_: &rars::ArchiveMember, _: &Error| {
            handler_calls.fetch_add(1, Ordering::Relaxed);
            Ok(rars::ExtractionErrorAction::Continue)
        };
        let error = archive
            .extract_with_control(
                ArchiveReadOptions::new().with_member_error_handler(&handler),
                |_| Ok(Decision::Extract(Box::new(io::sink()))),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::InvalidArchive);
        assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn selector_errors_preserve_existing_entry_context() {
    for version in VERSIONS {
        let archive = archive(version, false, false);
        let mut calls = 0;
        let error = archive
            .extract_with_control(ArchiveReadOptions::new(), |_| {
                calls += 1;
                Err(Error::InvalidHeader("selection failed")
                    .at_entry(b"external entry".to_vec(), "external operation"))
            })
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::InvalidArchive);
        assert_eq!(
            error.entry_context(),
            Some((b"external entry".as_slice(), "external operation"))
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn skip_and_stop_do_not_read_payloads_from_a_caller_source() {
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Source(Cursor<Vec<u8>>, Arc<AtomicBool>);
    impl Read for Source {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.1.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.0.read(bytes)
        }
    }
    impl Seek for Source {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.0.seek(from)
        }
    }
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![42; 1024], None, None)
            .unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let archive = ArchiveReader::read_reader(Source(
            Cursor::new(builder.to_bytes().unwrap()),
            fail.clone(),
        ))
        .unwrap();
        fail.store(true, Ordering::Relaxed);
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Skip))
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Stop))
                .unwrap(),
            Outcome::Stopped
        );
    }
}

#[test]
fn controlled_directory_extraction_selects_a_writer_without_spending_output_quota() {
    for version in VERSIONS {
        let mut builder = Builder::new(version);
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut visits = 0;
        let outcome = archive
            .extract_with_control(
                ArchiveReadOptions::new().with_max_total_output_bytes(0),
                |member| {
                    assert!(member.meta.is_directory);
                    visits += 1;
                    Ok(Decision::Extract(Box::new(Capture(output.clone()))))
                },
            )
            .unwrap();
        assert_eq!(outcome, Outcome::Complete);
        assert_eq!(visits, 1);
        assert!(output.borrow().is_empty());
    }
}

#[test]
fn a_solid_skip_budget_decodes_a_skipped_member_and_delivers_the_ones_after_it() {
    let mut state = 0x9e37_79b9u32;
    let middle: Vec<u8> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let first = b"before the large member".to_vec();
    // Only the skipped member's history can produce this one.
    let last = middle[1000..1300].to_vec();
    for version in VERSIONS {
        let mut builder = Builder::new(version).solid(true);
        for (name, data) in [
            (b"first".as_slice(), &first),
            (b"middle", &middle),
            (b"last", &last),
        ] {
            builder
                .add_bytes(name.to_vec(), data.clone(), None, None)
                .unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let skip_middle = |output: Extracted| {
            move |member: &rars::ArchiveMember| {
                Ok(match member.meta.name.as_slice() {
                    b"middle" => Decision::Skip,
                    name => {
                        let name = name.to_vec();
                        output.borrow_mut().push((name, Vec::new()));
                        let output = output.clone();
                        Decision::Extract(Box::new(Append(output)) as Box<dyn Write>)
                    }
                })
            }
        };
        // Output ceilings below the skipped member's size: it doesn't charge them.
        let options = ArchiveReadOptions::new()
            .with_max_member_output_bytes(512)
            .with_max_total_output_bytes(512);

        let error = archive
            .extract_with_control(options, skip_middle(Rc::default()))
            .unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::CannotSkipSolidMember),
            "{version:?}: {error}"
        );

        let output = Rc::new(RefCell::new(Vec::new()));
        let outcome = archive
            .extract_with_control(
                options.with_solid_skip_budget(8192),
                skip_middle(output.clone()),
            )
            .unwrap();
        assert_eq!(outcome, Outcome::Complete, "{version:?}");
        assert_eq!(
            *output.borrow(),
            vec![
                (b"first".to_vec(), first.clone()),
                (b"last".to_vec(), last.clone())
            ],
            "{version:?}"
        );

        let output = Rc::new(RefCell::new(Vec::new()));
        let error = archive
            .extract_with_control(
                options.with_solid_skip_budget(8191),
                skip_middle(output.clone()),
            )
            .unwrap_err();
        assert!(
            matches!(
                error.root_cause(),
                Error::SolidSkipBudgetExceeded {
                    limit: 8191,
                    required: 8192
                }
            ),
            "{version:?}: {error}"
        );
        assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
        assert_eq!(error.entry_context().unwrap().0, b"middle");
        // Refused on its declared size, so nothing after it was reached.
        assert_eq!(output.borrow().len(), 1, "{version:?}");
    }
}

/// Each extracted member's name and bytes, in order.
type Extracted = Rc<RefCell<Vec<(Vec<u8>, Vec<u8>)>>>;

/// Appends to the last member pushed onto the shared list.
struct Append(Extracted);
impl Write for Append {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .borrow_mut()
            .last_mut()
            .unwrap()
            .1
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
