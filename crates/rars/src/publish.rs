//! When publishing an archive by rename syncs it first.
//!
//! An archive is written beside its destination and renamed into place. A
//! rename onto an existing file can, after a crash, leave the new name pointing
//! at data that never reached the disk, and the old copy is gone with it. So
//! the new file is synced first. A rename onto a free name loses nothing in a
//! crash, and syncing it would only make the write wait for the disk: about 5 s
//! a GiB on a hard disk (#547). Nothing is synced then, as RAR does not.

use std::fs;
use std::io;
use std::path::Path;

/// Whether a rename onto `destination` replaces something there now. A
/// destination that cannot be looked at counts as there.
pub fn replaces_existing(destination: &Path) -> bool {
    match fs::symlink_metadata(destination) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

/// Syncs `output` if renaming it onto `destination` replaces an existing file.
pub fn sync_if_replacing(output: &fs::File, destination: &Path) -> io::Result<()> {
    if replaces_existing(destination) {
        output.sync_all()?;
    }
    Ok(())
}

/// Syncs the closed file at `staged` if renaming it onto `destination`
/// replaces an existing file.
pub fn sync_staged_if_replacing(staged: &Path, destination: &Path) -> io::Result<()> {
    if replaces_existing(destination) {
        // Windows syncs only a handle that can write.
        fs::OpenOptions::new()
            .write(true)
            .open(staged)?
            .sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::replaces_existing;

    #[test]
    fn only_an_existing_destination_is_replaced() {
        let root = crate::scratch::case("publish-replaces-existing");
        let file = root.join("archive.rar");
        assert!(!replaces_existing(&file), "a new archive is not synced");
        std::fs::write(&file, b"old").unwrap();
        assert!(
            replaces_existing(&file),
            "an existing archive is synced over"
        );
        let directory = root.join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(replaces_existing(&directory));
        #[cfg(unix)]
        {
            let dangling = root.join("dangling");
            std::os::unix::fs::symlink(root.join("missing"), &dangling).unwrap();
            assert!(
                replaces_existing(&dangling),
                "a link is replaced, not followed"
            );
        }
    }
}
