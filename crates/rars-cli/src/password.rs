use crate::{CliError, CliResult};
use rars::{Archive as DetectedArchive, ArchiveReader, Error};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) type Password = Zeroizing<Vec<u8>>;

pub(crate) fn password_bytes(password: &Option<Password>) -> Option<&[u8]> {
    password.as_deref().map(Vec::as_slice)
}

pub(crate) fn resolve_password(
    inline: Option<&str>,
    path: Option<&Path>,
) -> CliResult<Option<Password>> {
    if let Some(value) = inline {
        return Ok(Some(read_password_value(value)?));
    }
    if let Some(path) = path {
        if path == Path::new("-") {
            return Ok(Some(read_password_value("-")?));
        }
        let bytes = Zeroizing::new(fs::read(path).map_err(|error| {
            CliError::general(format!(
                "failed to read password file '{}': {error}",
                path.display()
            ))
        })?);
        return Ok(Some(trim_password_line(bytes)));
    }
    Ok(None)
}

fn read_password_value(value: &str) -> CliResult<Password> {
    if value == "-" {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)?;
        return Ok(trim_password_line(bytes));
    }
    Ok(Zeroizing::new(value.as_bytes().to_vec()))
}

fn trim_password_line(mut bytes: Password) -> Password {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    bytes
}

pub(crate) fn read_archive_path_prompting(
    path: &Path,
    password: &mut Option<Password>,
) -> CliResult<DetectedArchive> {
    read_archive_path_prompting_with_options(
        path,
        password,
        &crate::cli::ReadOptionsArgs::default(),
    )
}

pub(crate) fn read_archive_path_prompting_with_options(
    path: &Path,
    password: &mut Option<Password>,
    settings: &crate::cli::ReadOptionsArgs,
) -> CliResult<DetectedArchive> {
    match ArchiveReader::read_path_with_options(
        path,
        settings.options(password_bytes(password), None),
    ) {
        Ok(archive) => Ok(archive),
        Err(error) if password.is_none() && error_needs_password(&error) => {
            if let Some(prompted) = prompt_password_if_tty()? {
                *password = Some(prompted);
                ArchiveReader::read_path_with_options(
                    path,
                    settings.options(password_bytes(password), None),
                )
                .map_err(|err| read_archive_cli_error(path, err))
            } else {
                Err(read_archive_cli_error(path, error))
            }
        }
        Err(error) => Err(read_archive_cli_error(path, error)),
    }
}

pub(crate) fn parse_archives_prompting(
    paths: &[PathBuf],
    password: &mut Option<Password>,
    settings: &crate::cli::ReadOptionsArgs,
) -> CliResult<Vec<DetectedArchive>> {
    let mut archives = Vec::new();
    for path in paths {
        archives.push(read_archive_path_prompting_with_options(
            path, password, settings,
        )?);
    }
    Ok(archives)
}

pub(crate) fn ensure_password_for_archives_extract(
    archives: &[DetectedArchive],
    password: &mut Option<Password>,
) -> CliResult<()> {
    if password.is_none()
        && archives
            .iter()
            .any(|archive| archive.members().any(|member| member.meta.is_encrypted))
    {
        if let Some(prompted) = prompt_password_if_tty()? {
            *password = Some(prompted);
        }
    }
    Ok(())
}

pub(crate) fn ensure_password_for_extract(
    archive: &DetectedArchive,
    password: &mut Option<Password>,
) -> CliResult<()> {
    ensure_password_for_archives_extract(std::slice::from_ref(archive), password)
}

fn prompt_password_if_tty() -> CliResult<Option<Password>> {
    if !should_prompt_password(std::io::stdin().is_terminal()) {
        return Ok(None);
    }
    let line = rpassword::prompt_password("password: ")?;
    Ok(Some(trim_password_line(Zeroizing::new(line.into_bytes()))))
}

pub(crate) fn should_prompt_password(stdin_is_terminal: bool) -> bool {
    stdin_is_terminal
}

pub(crate) fn error_needs_password(error: &Error) -> bool {
    error.kind() == rars::ErrorKind::PasswordRequired
}

pub(crate) fn error_is_password_class(error: &Error) -> bool {
    matches!(
        error.kind(),
        rars::ErrorKind::PasswordRequired | rars::ErrorKind::BadPassword
    )
}

fn read_archive_error(path: &Path, err: Error) -> String {
    let path = path.display();
    match err.root_cause() {
        Error::Io(_) => format!("failed to read archive '{path}': {err}"),
        Error::UnsupportedSignature => format!("failed to identify archive '{path}': {err}"),
        _ => format!("failed to parse archive '{path}': {err}"),
    }
}

fn read_archive_cli_error(path: &Path, err: Error) -> CliError {
    let message = read_archive_error(path, err.clone());
    if error_is_password_class(&err) {
        CliError::password(message)
    } else {
        CliError::general(message)
    }
}

pub(crate) fn classify_rars_error(
    error: Error,
    message: impl FnOnce(&Error) -> String,
) -> CliError {
    if error_is_password_class(&error) {
        CliError::password(message(&error))
    } else {
        CliError::general(message(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_sources_preserve_bytes_spaces_and_explicit_empty_values() {
        let root = crate::scratch::case("password-source-bytes");
        let file = root.join("password");
        for (bytes, expected) in [
            (b" secret \r\n\n".as_slice(), b" secret ".as_slice()),
            (b"\xff\xfe\n", b"\xff\xfe"),
            (b"\r\n", b""),
        ] {
            fs::write(&file, bytes).unwrap();
            let password = resolve_password(None, Some(&file)).unwrap();
            assert_eq!(password_bytes(&password), Some(expected));
        }
        assert_eq!(
            password_bytes(&resolve_password(Some(""), None).unwrap()),
            Some(b"".as_slice())
        );
        assert_eq!(
            password_bytes(&resolve_password(Some("inline"), Some(&root.join("missing"))).unwrap()),
            Some(b"inline".as_slice())
        );
        assert!(resolve_password(None, None).unwrap().is_none());
        let missing = root.join("missing");
        let error = resolve_password(None, Some(&missing)).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("failed to read password file"));
        assert!(error.to_string().contains(&missing.display().to_string()));
        assert!(should_prompt_password(true));
        assert!(!should_prompt_password(false));
    }

    #[test]
    fn read_errors_keep_context_exit_class_and_message() {
        let path = Path::new("archive.rar");
        for (error, class, prefix) in [
            (Error::NeedPassword, 3, "failed to parse archive"),
            (
                Error::WrongPasswordOrCorruptData,
                3,
                "failed to parse archive",
            ),
            (Error::UnsupportedSignature, 1, "failed to identify archive"),
            (
                Error::UnsupportedVersion(rars::ArchiveVersion::Rar50),
                1,
                "failed to parse archive",
            ),
            (
                Error::from(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "denied",
                )),
                1,
                "failed to read archive",
            ),
        ] {
            let cli = read_archive_cli_error(path, error);
            assert_eq!(cli.exit_code(), class);
            assert!(cli.to_string().starts_with(prefix));
            assert!(cli.to_string().contains("archive.rar"));
        }
    }

    #[test]
    fn path_reading_preserves_passwords_and_stops_on_the_first_error() {
        let root = crate::scratch::case("password-path-read-errors");
        let path = root.join("plain.rar");
        let missing = root.join("missing.rar");
        let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        fs::write(&path, builder.to_bytes().unwrap()).unwrap();
        let mut password = None;
        let archive = read_archive_path_prompting(&path, &mut password).unwrap();
        ensure_password_for_extract(&archive, &mut password).unwrap();
        assert!(password.is_none());
        let parsed = parse_archives_prompting(
            std::slice::from_ref(&path),
            &mut password,
            &crate::cli::ReadOptionsArgs::default(),
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        let error = parse_archives_prompting(
            &[path.clone(), missing.clone()],
            &mut password,
            &crate::cli::ReadOptionsArgs::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error.exit_code(), 1);
        password = Some(Zeroizing::new(b"secret".to_vec()));
        let error = read_archive_path_prompting(&missing, &mut password)
            .err()
            .unwrap();
        assert_eq!(error.exit_code(), 1);
        assert_eq!(password_bytes(&password), Some(b"secret".as_slice()));
        let error = classify_rars_error(Error::InvalidHeader("broken"), |error| {
            format!("operation: {error}")
        });
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().starts_with("operation:"));
    }

    #[test]
    fn password_classification_survives_volume_context() {
        for (cause, needs_password, password_class) in [
            (Error::NeedPassword, true, true),
            (Error::WrongPasswordOrCorruptData, false, true),
            (Error::InvalidHeader("broken header"), false, false),
        ] {
            let volume = Error::InVolume {
                number: 2,
                source: Box::new(cause.clone()),
            };
            let nested = Error::AtEntry {
                name: b"file".to_vec(),
                operation: "extracting",
                source: Box::new(Error::AtArchiveOffset {
                    offset: 123,
                    source: Box::new(volume.clone()),
                }),
            };
            for error in [cause, volume, nested] {
                assert_eq!(error_needs_password(&error), needs_password, "{error}");
                assert_eq!(error_is_password_class(&error), password_class, "{error}");
            }
        }
    }
}
