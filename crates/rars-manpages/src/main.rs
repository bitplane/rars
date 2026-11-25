//! Writes the `rars` man pages to `man/` and its shell completions to
//! `completions/`, from the clap definition the binary parses with. `just
//! manpages` runs it; CI runs it too and fails if the committed files differ.
//!
//! `man/unrars.1` is written by hand, since `unrars` parses unrar's syntax
//! without clap, and is left alone here.
//!
//! Usage: `rars-manpages [ROOT]`, where ROOT holds `man/` and `completions/`
//! and defaults to the workspace root.

use clap_complete::{Generator, Shell};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() -> io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let mut command = rars_cli::command();
    // Fills in what subcommands inherit: global options, bin names such as
    // `rars add` and display names such as `rars-add`.
    command.build();
    write_man_pages(&command, &root.join("man"))?;
    write_completions(&mut command, &root.join("completions"))
}

/// `rars.1`, and a `rars-<subcommand>.1` for each subcommand with its options.
fn write_man_pages(command: &clap::Command, dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    // A page for a subcommand that no longer exists would otherwise stay.
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str());
        if name.is_some_and(|name| name == "rars.1" || name.starts_with("rars-")) {
            fs::remove_file(&path)?;
        }
    }
    let mut pages = vec![command.clone()];
    pages.extend(
        command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .cloned(),
    );
    for page in pages {
        let title = page
            .get_display_name()
            .unwrap_or(page.get_name())
            .to_owned();
        let man = clap_mangen::Man::new(page);
        let mut roff = Vec::new();
        man.render(&mut roff)?;
        let roff = String::from_utf8(roff).map_err(io::Error::other)?;
        fs::write(dir.join(man.get_filename()), finish_page(&roff, &title))?;
    }
    Ok(())
}

/// Writes the title line with an empty date quoted, which clap_mangen leaves
/// bare so that the next field slides into its place, and with the source
/// unversioned. Drops the VERSION section, so a release's version bump leaves
/// the pages as they are. Names the section `after_help` fills for what it
/// holds, the exit codes, and spells characters beyond ASCII, such as the em
/// dashes in the help, as roff escapes, which troff reads without preconv.
fn finish_page(roff: &str, title: &str) -> String {
    let mut page = String::with_capacity(roff.len());
    let mut skipping = false;
    for line in roff.split_inclusive('\n') {
        if line.starts_with(".TH ") {
            page.push_str(&format!(".TH {title} 1 \"\" rars\n"));
            continue;
        }
        if line.starts_with(".SH ") {
            skipping = line.trim_end() == ".SH VERSION";
        }
        if skipping {
            continue;
        }
        if line.trim_end() == ".SH EXTRA" {
            page.push_str(".SH \"EXIT STATUS\"\n");
            continue;
        }
        for character in line.chars() {
            if character.is_ascii() {
                page.push(character);
            } else {
                page.push_str(&format!("\\[u{:04X}]", u32::from(character)));
            }
        }
    }
    page
}

/// One script per shell, under the file name clap_complete gives it.
fn write_completions(command: &mut clap::Command, dir: &Path) -> io::Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    for shell in [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Elvish,
    ] {
        let mut script = Vec::new();
        clap_complete::generate(shell, command, "rars", &mut script);
        fs::write(dir.join(shell.file_name("rars")), script)?;
    }
    Ok(())
}
