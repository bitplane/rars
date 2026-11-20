use rars::write_plan::*;

use rars::{ArchiveVersion, Error, Feature, PlanShape, WriterOption};

/// The capability table and the validator have to agree everywhere, or a
/// caller can be told an option is available and then refused it.
#[test]
fn asking_and_validating_agree_for_every_combination() {
    for target in ArchiveVersion::ALL {
        for option in WriterOption::ALL {
            for shape in PlanShape::all() {
                let supported = supports(target, option, shape);
                let validated = validate_option(target, option, shape);
                assert_eq!(
                    supported,
                    validated.is_ok(),
                    "{target} {option:?} {shape:?}: supports={supported} validate={validated:?}"
                );
                if let Err(Error::UnsupportedWriterOption { option: named, .. }) = validated {
                    assert_eq!(named, option, "the refusal named the wrong option");
                }
            }
        }
    }
}

/// The format-support cells of `docs/writer-limits.md`, pinned so a
/// writer that gains or loses one has to update the table too.
#[test]
#[cfg(all(feature = "encryption", feature = "recovery"))]
fn writer_limits_table_matches_what_each_format_supports() {
    const WRITER_LIMITS_TABLE: &str = "\
        rar13 single  solid password --- -------- memory temp\n\
        rar13 volumes solid -------- --- -------- ------ temp\n\
        rar14 single  solid password --- -------- memory temp\n\
        rar14 volumes solid -------- --- -------- ------ temp\n\
        rar15 single  solid password --- -------- memory temp\n\
        rar15 volumes solid password --- -------- ------ ----\n\
        rar20 single  solid password --- -------- memory temp\n\
        rar20 volumes solid password --- -------- ------ ----\n\
        rar29 single  solid password -hp -------- memory temp\n\
        rar29 volumes solid password -hp -------- ------ ----\n\
        rar30 single  solid password -hp -------- memory temp\n\
        rar30 volumes solid password -hp -------- ------ ----\n\
        rar40 single  solid password -hp -------- memory temp\n\
        rar40 volumes solid password -hp -------- ------ ----\n\
        rar50 single  solid password -hp recovery memory temp\n\
        rar50 volumes solid password -hp recovery memory temp\n\
        rar70 single  solid password -hp recovery memory temp\n\
        rar70 volumes solid password -hp recovery memory temp\n\
    ";
    let columns = [
        ("solid", WriterOption::Feature(Feature::Solid)),
        ("password", WriterOption::Password),
        ("-hp", WriterOption::Feature(Feature::HeaderEncryption)),
        ("recovery", WriterOption::RecoveryRecord),
        ("memory", WriterOption::MemoryLimit),
        ("temp", WriterOption::TempDir),
    ];
    let mut table = String::new();
    for target in ArchiveVersion::ALL {
        for volumes in [false, true] {
            let shape = PlanShape::new().compressed(true).volumes(volumes);
            let shape_name = if volumes { "volumes" } else { "single" };
            table.push_str(&format!("{target:<6} {shape_name:<7}"));
            for (name, option) in columns {
                if supports(target, option, shape) {
                    table.push_str(&format!(" {name}"));
                } else {
                    table.push_str(&format!(" {}", "-".repeat(name.len())));
                }
            }
            table.push('\n');
        }
    }
    assert_eq!(table, WRITER_LIMITS_TABLE, "\n{table}");
}

/// A refusal is only useful if it can point somewhere, so every option has
/// to be available on at least one format.
#[test]
fn every_option_is_supported_by_some_format() {
    for option in WriterOption::ALL {
        assert!(!option.name().is_empty());
        let disabled = match option {
            WriterOption::Password | WriterOption::Feature(Feature::HeaderEncryption) => {
                !cfg!(feature = "encryption")
            }
            WriterOption::RecoveryRecord => !cfg!(feature = "recovery"),
            _ => false,
        };
        assert_eq!(
            PlanShape::all()
                .into_iter()
                .any(|shape| !formats_supporting(option, shape).is_empty()),
            !disabled,
            "{option:?} must have a supporting format exactly when its capability is enabled"
        );
    }
}

#[test]
fn a_level_above_five_is_refused_by_name() {
    let refused = validate_compression_level(ArchiveVersion::Rar50, Some(9));
    assert!(matches!(
        refused,
        Err(Error::UnsupportedWriterOption {
            option: WriterOption::CompressionLevel,
            ..
        })
    ));
    assert!(validate_compression_level(ArchiveVersion::Rar50, Some(5)).is_ok());
    assert!(validate_compression_level(ArchiveVersion::Rar50, None).is_ok());
}
