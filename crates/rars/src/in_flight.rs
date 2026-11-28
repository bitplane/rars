use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Outputs not yet in place, by destination relative to the output directory.
#[derive(Default)]
pub struct InFlight {
    paths: HashMap<PathBuf, Counts>,
}

/// Below counts outputs under the path, which a file there would collide with.
#[derive(Default)]
struct Counts {
    files: usize,
    directories: usize,
    below: usize,
}

impl InFlight {
    pub fn add(&mut self, relative: &Path, directory: bool) {
        for above in parents(relative) {
            self.paths.entry(above.to_path_buf()).or_default().below += 1;
        }
        let counts = self.paths.entry(relative.to_path_buf()).or_default();
        if directory {
            counts.directories += 1;
        } else {
            counts.files += 1;
        }
    }

    pub fn remove(&mut self, relative: &Path, directory: bool) {
        let mut forget = |path: &Path, count: fn(&mut Counts) -> &mut usize| {
            if let Some(counts) = self.paths.get_mut(path) {
                *count(counts) -= 1;
                if counts.files + counts.directories + counts.below == 0 {
                    self.paths.remove(path);
                }
            }
        };
        if directory {
            forget(relative, |counts| &mut counts.directories);
        } else {
            forget(relative, |counts| &mut counts.files);
        }
        for above in parents(relative) {
            forget(above, |counts| &mut counts.below);
        }
    }

    /// Whether these outputs can change what opening finds at `relative`.
    pub fn changes(&self, relative: &Path, directory: bool) -> bool {
        if self.paths.is_empty() {
            return false;
        }
        if let Some(counts) = self.paths.get(relative) {
            if counts.files > 0 || !directory && (counts.directories > 0 || counts.below > 0) {
                return true;
            }
        }
        parents(relative).any(|above| self.paths.get(above).is_some_and(|counts| counts.files > 0))
    }
}

/// The directories above `relative`, not counting the output directory.
fn parents(relative: &Path) -> impl Iterator<Item = &Path> {
    relative
        .ancestors()
        .skip(1)
        .take_while(|above| !above.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_outputs_change_what_is_at_their_path_and_around_it() {
        let mut queued = InFlight::default();
        queued.add(Path::new("a/b"), false);
        queued.add(Path::new("d"), true);
        // A file there, a file above, or for a file anything below.
        assert!(queued.changes(Path::new("a/b"), true));
        assert!(queued.changes(Path::new("a/b/c"), false));
        assert!(queued.changes(Path::new("a"), false));
        assert!(!queued.changes(Path::new("a"), true));
        assert!(queued.changes(Path::new("d"), false));
        assert!(!queued.changes(Path::new("d"), true));
        assert!(!queued.changes(Path::new("d/e"), false));
        queued.remove(Path::new("a/b"), false);
        assert!(!queued.changes(Path::new("a"), false));
        assert!(!queued.changes(Path::new("a/b/c"), false));
    }
}
