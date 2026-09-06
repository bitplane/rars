use crate::{CliError, CliResult};
use rars::{Archive as DetectedArchive, ArchiveReadOptions, ArchiveReader, Error};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) type Password = Zeroizing<Vec<u8>>;

pub(crate) fn password_bytes(password: &Option<Password>) -> Option<&[u8]> {
    password.as_deref().map(Vec::as_slice)
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

pub(crate) fn resolve_password(
    inline: Option<&str>,
    path: Option<&Path>,
) -> CliResult<Option<Password>> {
    if let Some(value) = inline {
        return Ok(Some(read_password_value(value)?));
    }
    if let Some(path) = path {
        let bytes = Zeroizing::new(fs::read(path)?);
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
    match ArchiveReader::read_path_with_options(path, read_options(password_bytes(password))) {
        Ok(archive) => Ok(archive),
        Err(error) if password.is_none() && error_needs_password(&error) => {
            if let Some(prompted) = prompt_password_if_tty()? {
                *password = Some(prompted);
                ArchiveReader::read_path_with_options(path, read_options(password_bytes(password)))
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
) -> CliResult<Vec<DetectedArchive>> {
    let mut archives = Vec::new();
    for path in paths {
        archives.push(read_archive_path_prompting(path, password)?);
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
    match err.kind() {
        rars::ErrorKind::Io => format!("failed to read archive '{path}': {err}"),
        rars::ErrorKind::UnsupportedFormat
            if matches!(err.root_cause(), Error::UnsupportedSignature) =>
        {
            format!("failed to identify archive '{path}': {err}")
        }
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
