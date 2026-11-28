use rars::{Archive as DetectedArchive, ExtractedEntryMeta};
use std::path::Path;

pub(crate) use rars::extract_engine::{restore_output_metadata, ExtractedOutput};
pub(crate) use rars::output_staging::OverwritePolicy;

pub(crate) fn print_ok_entry(entry: &ExtractedEntryMeta) {
    print_ok_name(&entry.name, entry.is_directory);
}

pub(crate) fn print_ok_name(name: &[u8], is_directory: bool) {
    println!(
        "OK {}{}",
        display_archive_bytes(name),
        if is_directory { "/" } else { "" }
    );
}

pub(crate) fn print_engine_warnings(engine: &mut rars::extract_engine::ExtractEngine<'_>) {
    engine.warn_to(Box::new(|warning| match warning {
        rars::extract_engine::Warning::Unnamed => {
            eprintln!("warning: skipping a member with no name");
        }
        rars::extract_engine::Warning::SkippedLink { name, target, .. } => {
            eprintln!("{}", skipped_link_warning(name, target));
        }
    }));
}

pub(crate) fn warn_rar50_redirections(archive: &DetectedArchive) {
    let DetectedArchive::Rar50Plus(archive) = archive else {
        return;
    };
    for file in archive.files().filter(|file| file.redirection.is_some()) {
        eprintln!("{}", redirection_warning(file.name_lossy()));
    }
}

pub(crate) fn redirection_warning(name: impl AsRef<str>) -> String {
    format!(
        "warning: RAR 5 redirection entry '{}' is not recreated; extraction treats only regular file payloads as writable output",
        display_archive_text(name.as_ref())
    )
}

pub(crate) fn incomplete_member_warning(volume: &Path, member: &rars::IncompleteMember) -> String {
    let missing = match member.missing {
        rars::MissingPart::Start => "its start is in a missing earlier volume",
        rars::MissingPart::End => "its end is in a missing later volume",
        _ => "its start and end are in missing volumes",
    };
    format!(
        "warning: {}: skipped split member '{}': {missing}",
        volume.display(),
        display_archive_bytes(&member.name)
    )
}

/// A member `test` or `x` failed on and went past. `hint` follows the error.
pub(crate) fn damaged_member_warning(
    path: &Path,
    name: &[u8],
    error: &rars::Error,
    hint: &str,
) -> String {
    match error.entry_context() {
        Some(_) => format!("warning: {}: {error}{hint}", path.display()),
        None => format!(
            "warning: {}: '{}': {error}{hint}",
            path.display(),
            display_archive_bytes(name)
        ),
    }
}

/// A damaged member `x --keep-broken` kept, with what was read of it.
pub(crate) fn kept_broken_warning(path: &Path, name: &[u8], error: &rars::Error) -> String {
    format!(
        "warning: {}: '{}': kept broken: {}",
        path.display(),
        display_archive_bytes(name),
        error.root_cause()
    )
}

pub(crate) fn truncation_warning(path: &Path, truncation: &rars::Truncation) -> String {
    format!("warning: {}: archive is {truncation}", path.display())
}

/// Warns that an archive ends early, about each malformed block its reader
/// passed over, and about each damaged header a salvaging read went past.
pub(crate) fn warn_archive_structure(path: &Path, archive: &DetectedArchive) {
    for damage in archive.header_damage() {
        eprintln!("warning: {}: {damage}", path.display());
    }
    for skipped in archive.skipped_blocks() {
        eprintln!("warning: {}: {skipped}", path.display());
    }
    if let Some(truncation) = archive.truncation() {
        eprintln!("{}", truncation_warning(path, truncation));
    }
}

pub(crate) fn skipped_link_warning(name: &[u8], target: &[u8]) -> String {
    format!(
        "warning: skipping link '{}' -> '{}': it would point outside the output directory",
        display_archive_bytes(name),
        display_archive_bytes(target)
    )
}

fn display_archive_text(text: impl AsRef<str>) -> String {
    let mut out = String::new();
    for ch in text.as_ref().chars() {
        // Escape control characters (e.g. terminal escape sequences) so a
        // hostile archive name can't manipulate the terminal, but pass
        // printable Unicode such as Cyrillic or CJK through unchanged.
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

fn display_archive_bytes(bytes: &[u8]) -> String {
    display_archive_text(String::from_utf8_lossy(bytes))
}

#[cfg(test)]
mod tests {
    use super::display_archive_text;

    #[test]
    fn display_archive_text_keeps_unicode_and_escapes_controls() {
        assert_eq!(
            display_archive_text("ваапап/WinRAR.exe"),
            "ваапап/WinRAR.exe"
        );
        assert_eq!(
            display_archive_text("x\u{1b}]0;evil\u{7}"),
            "x\\u{1b}]0;evil\\u{7}"
        );
    }
}
