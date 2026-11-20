use rars::error::*;

use rars::{ArchiveFamily, ArchiveVersion, Error};

#[test]
fn machine_readable_codes_remain_stable_and_distinct() {
    let cases = [
        (ErrorKind::InvalidArchive, "INVALID_ARCHIVE"),
        (ErrorKind::InvalidArgument, "INVALID_OPTION"),
        (ErrorKind::UnsupportedFormat, "UNSUPPORTED_FORMAT"),
        (ErrorKind::UnsupportedFeature, "UNSUPPORTED_FEATURE"),
        (ErrorKind::PasswordRequired, "PASSWORD_REQUIRED"),
        (ErrorKind::BadPassword, "BAD_PASSWORD"),
        (ErrorKind::ChecksumMismatch, "CHECKSUM_MISMATCH"),
        (ErrorKind::EntryNotFound, "ENTRY_NOT_FOUND"),
        (ErrorKind::DuplicateEntry, "DUPLICATE_ENTRY"),
        (ErrorKind::UnsafePath, "UNSAFE_ENTRY_NAME"),
        (ErrorKind::Io, "IO"),
        (ErrorKind::ResourceLimit, "RESOURCE_LIMIT"),
        (ErrorKind::Cancelled, "CANCELLED"),
        (ErrorKind::SourceChanged, "SOURCE_CHANGED"),
        (ErrorKind::WriterFailure, "WRITE_FAILED"),
    ];
    let mut codes = std::collections::HashSet::new();
    for (kind, expected) in cases {
        assert_eq!(kind.code(), expected);
        assert!(codes.insert(kind.code()), "duplicate error code {expected}");
    }
}

#[test]
fn resource_diagnostics_retain_required_used_and_limit_values() {
    let cases = [
        (
            Error::Rar50ScratchLimitExceeded { limit: 11, required: 23 },
            "RAR 5 scratch limit 11 bytes exceeded (requires 23)",
        ),
        (
            Error::Rar50FilterMemoryLimitExceeded { limit: 11, required: 23 },
            "RAR 5 filter workspace limit 11 bytes exceeded (requires 23)",
        ),
        (
            Error::WriterSpoolLimitExceeded { limit: 11, required: 23, used: 7 },
            "writer spool limit 11 bytes exceeded (requires 23; 7 bytes already retained or reserved)",
        ),
        (
            Error::WriterPreparationLimitExceeded { limit: 11, required: 23, used: 7 },
            "writer preparation limit 11 bytes exceeded (requires 23; 7 bytes already retained or reserved)",
        ),
        (
            Error::WriterPreparedHeaderLimitExceeded { limit: 11, required: 23, used: 7 },
            "writer prepared header limit 11 bytes exceeded (requires 23; 7 bytes already retained or reserved)",
        ),
        (
            Error::WriterSpoolMemoryLimitExceeded { limit: 11, required: 23, used: 7 },
            "writer spool memory limit 11 bytes exceeded (requires 23; 7 bytes already retained or reserved)",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert_eq!(error.to_string(), expected);
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(
        Error::CannotSkipSolidMember.to_string(),
        "cannot skip file data in a solid archive"
    );
    assert_eq!(
        Error::CannotSkipSolidMember.kind(),
        ErrorKind::UnsupportedFeature
    );
    assert!(Error::CannotSkipSolidMember.entry_context().is_none());
    // The archive may be fine: the earlier member could have failed on
    // its sink or been cancelled.
    assert_eq!(
        Error::BrokenSolidChain.kind(),
        ErrorKind::UnsupportedFeature
    );
}

#[test]
fn codec_io_transport_retains_library_error_types() {
    for cause in [
        Error::Cancelled,
        Error::NeedPassword,
        Error::MemberOutputLimitExceeded {
            limit: 1,
            required: 2,
        },
    ] {
        let transported = rars::codec::Error::from(std::io::Error::other(cause.clone()));
        assert_eq!(Error::from(transported.clone()), cause);
        assert_eq!(Error::Codec(transported).kind(), cause.kind());
    }
}

#[test]
fn codec_workspace_refusal_keeps_its_resource_classification_and_details() {
    let cause =
        rars::codec::Error::WorkspaceLimitExceeded(Box::new(rars::codec::WorkspaceLimitError {
            limit: 12,
            required: 16,
            used: 8,
        }));
    let error = Error::from(cause.clone()).at_archive_offset(42);
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert!(matches!(error.root_cause(), Error::Codec(actual) if actual == &cause));
    assert!(error.to_string().contains("codec workspace limit 12"));
}

#[test]
fn classification_survives_every_context_order_without_losing_details() {
    let cases = [
        (Error::NeedPassword, ErrorKind::PasswordRequired),
        (
            Error::Rar50Crypto(rars::crypto::rar50::Error::BadPassword),
            ErrorKind::BadPassword,
        ),
        (
            Error::UnsupportedCompression {
                family: "RAR",
                unpack_version: 99,
                method: 9,
            },
            ErrorKind::UnsupportedFeature,
        ),
        (
            Error::UnsupportedVersion(ArchiveVersion::Rar50),
            ErrorKind::UnsupportedFormat,
        ),
        (
            Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            ErrorKind::Io,
        ),
        (
            Error::Rar5Recovery(rars::recovery::rar5::Error::Io(
                std::io::ErrorKind::WriteZero,
            )),
            ErrorKind::Io,
        ),
        (
            Error::MemoryLimitExceeded {
                limit: 1,
                required: 2,
                dictionary_size: 1,
            },
            ErrorKind::ResourceLimit,
        ),
        (
            Error::TotalOutputLimitExceeded {
                limit: 100,
                required: 110,
                used: 60,
            },
            ErrorKind::ResourceLimit,
        ),
        (
            Error::Codec(rars::codec::Error::Cancelled),
            ErrorKind::Cancelled,
        ),
        (
            Error::HeaderCountLimitExceeded {
                limit: 1,
                required: 2,
            },
            ErrorKind::ResourceLimit,
        ),
        (
            Error::HeaderBytesLimitExceeded {
                limit: 1,
                required: 2,
            },
            ErrorKind::ResourceLimit,
        ),
        (Error::Cancelled, ErrorKind::Cancelled),
        (
            Error::WriterFailure("layout failure"),
            ErrorKind::WriterFailure,
        ),
        (Error::VolumeOutOfOrder, ErrorKind::InvalidArchive),
        (Error::EntryNotFound, ErrorKind::EntryNotFound),
        (Error::DuplicateEntry, ErrorKind::DuplicateEntry),
        (Error::InputSymlink, ErrorKind::InvalidArgument),
        (Error::UnsafePath("path refusal"), ErrorKind::UnsafePath),
        (
            Error::SourceChanged("changed source"),
            ErrorKind::SourceChanged,
        ),
        (
            Error::InvalidHeader("password is required; unsafe; I/O error"),
            ErrorKind::InvalidArchive,
        ),
        (
            Error::HashMismatch { hash_type: 0 },
            ErrorKind::ChecksumMismatch,
        ),
    ];
    for (cause, expected) in cases {
        assert_eq!(cause.kind(), expected);
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut wrapped = cause.clone();
            for wrapper in order {
                wrapped = match wrapper {
                    0 => wrapped.at_archive_offset(42),
                    1 => wrapped.at_entry(b"member".to_vec(), "reading"),
                    _ => Error::InVolume {
                        index: 2,
                        source: Box::new(wrapped),
                    },
                };
            }
            assert_eq!(wrapped.kind(), expected);
            assert_eq!(wrapped.root_cause(), &cause);
            assert_eq!(
                wrapped.entry_context(),
                Some((b"member".as_slice(), "reading"))
            );
            assert!(wrapped.to_string().contains("in volume 3"));
            assert!(wrapped.to_string().contains("member"));
        }
    }
}

#[test]
fn archive_offset_context_exposes_source_error() {
    let error = Error::InvalidHeader("bad block").at_archive_offset(0x1234);

    assert_eq!(
        error.to_string(),
        "at archive offset 0x1234: invalid header: bad block"
    );
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("invalid header: bad block".to_string())
    );
}

#[test]
fn entry_context_exposes_source_error() {
    let error = Error::Crc32Mismatch {
        expected: 1,
        actual: 2,
    }
    .at_entry(b"hello.txt".to_vec(), "verifying");

    assert_eq!(
        error.to_string(),
        "while verifying entry 'hello.txt': checksum mismatch: expected 0x00000001, got 0x00000002"
    );
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("checksum mismatch: expected 0x00000001, got 0x00000002".to_string())
    );
}

#[test]
fn io_error_preserves_error_kind() {
    let error = Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "locked",
    ));

    assert!(matches!(
        error,
        Error::Io(ref source) if source.kind == std::io::ErrorKind::PermissionDenied
    ));
    assert_eq!(error.to_string(), "I/O error: locked");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("locked".to_string())
    );
}

#[test]
fn io_error_partial_eq_compares_kind_and_message_ignoring_source_identity() {
    let permission = Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "locked",
    ));
    let permission_again = Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "locked",
    ));
    let different_kind = Error::from(std::io::Error::new(std::io::ErrorKind::NotFound, "locked"));
    let different_message = Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "elsewhere",
    ));

    // Same kind + same message → equal even though Arc<io::Error> differs.
    assert_eq!(permission, permission_again);
    // Differing kind or message → not equal.
    assert_ne!(permission, different_kind);
    assert_ne!(permission, different_message);
}

#[test]
fn unsupported_codec_errors_are_not_reported_as_invalid_headers() {
    assert_eq!(
        Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: 14,
            method: 0x33,
        }
        .to_string(),
        "RAR 1.5-4.x compression is not supported: unpack version 14, method 0x33"
    );
    assert_eq!(
        Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x",
            unpack_version: 14,
        }
        .to_string(),
        "RAR 1.5-4.x encryption is not supported: unpack version 14"
    );
}

#[test]
fn codec_errors_remain_inspectable_without_changing_display_text() {
    let error = Error::from(rars::codec::Error::NeedMoreInput);

    assert!(matches!(
        error,
        Error::Codec(rars::codec::Error::NeedMoreInput)
    ));
    assert_eq!(error.to_string(), "codec input is truncated");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("codec input is truncated".to_string())
    );
}

#[test]
fn recovery_errors_remain_inspectable_without_changing_display_text() {
    let error = Error::from(rars::recovery::rar5::Error::TooManyDamagedShards);

    assert!(matches!(
        error,
        Error::Rar5Recovery(rars::recovery::rar5::Error::TooManyDamagedShards)
    ));
    assert_eq!(
        error.to_string(),
        "RAR 5 recovery data cannot repair this many damaged shards"
    );
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("RAR 5 recovery data cannot repair this many damaged shards".to_string())
    );
}

#[test]
fn rar3_recovery_errors_remain_in_source_chain() {
    let error = Error::from(rars::recovery::rar3::Error::DecodeFailed);

    assert_eq!(error.to_string(), "RAR 3 recovery decode failed");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("RAR 3 recovery decode failed".to_string())
    );
}

#[test]
fn rar30_crypto_errors_remain_in_source_chain() {
    let error = Error::from(rars::crypto::rar30::Error::UnalignedInput);

    assert!(matches!(
        error,
        Error::Rar30Crypto(rars::crypto::rar30::Error::UnalignedInput)
    ));
    assert_eq!(error.to_string(), "RAR 3.x AES input is not block aligned");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("RAR 3.x AES input is not block aligned".to_string())
    );
}

#[test]
fn rar20_crypto_errors_remain_in_source_chain() {
    let error = Error::from(rars::crypto::rar20::Error::UnalignedInput);

    assert!(matches!(
        error,
        Error::Rar20Crypto(rars::crypto::rar20::Error::UnalignedInput)
    ));
    assert_eq!(
        error.to_string(),
        "RAR 2.0 cipher input is not block aligned"
    );
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("RAR 2.0 cipher input is not block aligned".to_string())
    );
}

#[test]
fn rar50_crypto_errors_remain_in_source_chain() {
    let error = Error::from(rars::crypto::rar50::Error::UnalignedInput);

    assert_eq!(error.to_string(), "RAR 5 AES input is not block aligned");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("RAR 5 AES input is not block aligned".to_string())
    );
}

#[test]
fn simple_display_variants_render_their_messages() {
    assert_eq!(Error::TooShort.to_string(), "input is too short");
    assert_eq!(
        Error::UnsupportedSignature.to_string(),
        "unsupported archive signature"
    );
    assert_eq!(Error::NeedPassword.to_string(), "a password is required");
    assert_eq!(
        Error::WrongPasswordOrCorruptData.to_string(),
        "wrong password or corrupt encrypted data"
    );
    assert_eq!(
        Error::HashMismatch { hash_type: 7 }.to_string(),
        "hash mismatch for hash type 7"
    );
    assert_eq!(
        Error::CrcMismatch {
            expected: 0xabcd,
            actual: 0x1234
        }
        .to_string(),
        "checksum mismatch: expected 0xabcd, got 0x1234"
    );
    assert_eq!(
        Error::UnsupportedVersion(ArchiveVersion::Rar50).to_string(),
        "unsupported version: rar50"
    );
    assert_eq!(
        Error::UnsupportedFeature {
            version: ArchiveVersion::Rar50,
            feature: "quantum compression",
        }
        .to_string(),
        "feature quantum compression is not supported by rar50"
    );
    assert_eq!(
        Error::Rar50BufferedDecodeLimitExceeded {
            limit: 536_870_912,
            required: 734_003_200,
        }
        .to_string(),
        "RAR 5 filtered member requires buffered decoding of 734003200 bytes, above the configured limit of 536870912 bytes"
    );
}

#[test]
fn rar3_recovery_errors_render_messages_through_from_conversion() {
    assert_eq!(
        Error::from(rars::recovery::rar3::Error::InvalidParitySize).to_string(),
        "RAR 3 recovery parity size is invalid"
    );
    assert_eq!(
        Error::from(rars::recovery::rar3::Error::InvalidCodewordSize).to_string(),
        "RAR 3 recovery codeword size is invalid"
    );
    assert_eq!(
        Error::from(rars::recovery::rar3::Error::TooManyErasures).to_string(),
        "RAR 3 recovery data cannot repair this many erasures"
    );
    assert_eq!(
        Error::from(rars::recovery::rar3::Error::DecodeFailed).to_string(),
        "RAR 3 recovery decode failed"
    );
}

#[test]
fn rar5_recovery_errors_render_messages_for_every_named_variant() {
    let cases = [
        (
            rars::recovery::rar5::Error::BadRecoveryChunk,
            "RAR 5 recovery chunk is invalid",
        ),
        (
            rars::recovery::rar5::Error::OddShardSize,
            "RAR 5 recovery shard size is odd",
        ),
        (
            rars::recovery::rar5::Error::PlanOverflow,
            "RAR 5 recovery plan overflows",
        ),
        (
            rars::recovery::rar5::Error::PrefixExceedsPlan,
            "RAR 5 recovery prefix exceeds planned shard capacity",
        ),
        (
            rars::recovery::rar5::Error::ShardSizeMismatch,
            "RAR 5 recovery shard sizes differ",
        ),
        (
            rars::recovery::rar5::Error::TooManyShards,
            "RAR 5 recovery shard count is invalid",
        ),
        (
            rars::recovery::rar5::Error::SingularElement,
            "RAR 5 recovery matrix is singular",
        ),
    ];
    for (variant, expected) in cases {
        assert_eq!(Error::from(variant).to_string(), expected);
    }
}

#[test]
fn rar50_crypto_errors_render_messages_through_from_conversion() {
    assert_eq!(
        Error::from(rars::crypto::rar50::Error::KdfCountTooLarge).to_string(),
        "RAR 5 KDF count is too large"
    );
    assert_eq!(
        Error::from(rars::crypto::rar50::Error::BadPassword).to_string(),
        "wrong password or corrupt encrypted data"
    );
}

#[test]
fn codec_invalid_data_display_uses_inner_message() {
    assert_eq!(
        Error::from(rars::codec::Error::InvalidData("bad symbol")).to_string(),
        "bad symbol"
    );
}

#[test]
fn unsupported_family_feature_display_renders_family_and_feature() {
    assert_eq!(
        Error::UnsupportedFamilyFeature {
            family: ArchiveFamily::Rar13,
            feature: "recovery repair for RAR 1.3/1.4 archives",
        }
        .to_string(),
        "feature recovery repair for RAR 1.3/1.4 archives is not supported by Rar13",
    );
}

#[test]
fn rar50_crypto_unaligned_input_display_uses_named_message() {
    assert_eq!(
        Error::from(rars::crypto::rar50::Error::UnalignedInput).to_string(),
        "RAR 5 AES input is not block aligned"
    );
}
