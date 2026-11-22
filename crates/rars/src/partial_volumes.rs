//! Reading what survives of a volume set with volumes missing.

use crate::Archive;

/// Which ends of a split member lie in volumes that were not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MissingPart {
    /// The member starts in an earlier volume.
    Start,
    /// The member continues into a later volume.
    End,
    /// The member starts before and continues after the volumes given.
    Both,
}

/// A split member [`drop_incomplete_members`] removed because part of it is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IncompleteMember {
    /// The stored name of the first fragment present.
    pub name: Vec<u8>,
    /// Index, among the volumes given, of the first one holding part of the member.
    pub volume: usize,
    pub missing: MissingPart,
}

/// Removes the fragments of every split member whose start or end lies
/// outside `volumes`, and returns those members in archive order.
///
/// `volumes` are consecutive volumes of one set, as the volume functions take
/// them, but the set may begin late or end early. Afterwards every member
/// left starts and ends inside them, so they can be tested or extracted as
/// usual: with [`crate::test_volumes_with_options_and_callback`] and
/// [`crate::extract_volumes_with_links`], or on its own for a single volume.
/// A complete set loses nothing. A continuation that does not match the
/// member before it (a different method, encryption or known size) is taken
/// as a break in the set: the member before it is missing its end, and the
/// continuation its start. Archives that are not volumes are left alone.
pub fn drop_incomplete_members(volumes: &mut [Archive]) -> Vec<IncompleteMember> {
    let mut incomplete = Vec::new();
    let mut drops = Vec::new();
    let mut running: Option<Chain> = None;
    for (index, volume) in volumes.iter().enumerate() {
        let (first, last) = split_ends(volume);
        let carried = running.take().and_then(|mut chain| match &first {
            Some(first) if chain.key.continues_as(&first.key) => {
                // Once a fragment states the size, the rest must agree with it.
                chain.key.size = chain.key.size.or(first.key.size);
                Some(chain)
            }
            _ => {
                chain.close(true, &mut incomplete, &mut drops);
                None
            }
        });
        if let Some(first) = first {
            let mut chain = carried.unwrap_or_else(|| Chain::new(index, &first, true));
            chain.fragments.push((index, End::First));
            if first.after {
                running = Some(chain);
                continue;
            }
            chain.close(false, &mut incomplete, &mut drops);
        }
        if let Some(last) = last {
            let mut chain = Chain::new(index, &last, false);
            chain.fragments.push((index, End::Last));
            running = Some(chain);
        }
    }
    if let Some(chain) = running {
        chain.close(true, &mut incomplete, &mut drops);
    }
    for (index, end) in drops {
        remove_file(&mut volumes[index], end);
    }
    incomplete
}

#[derive(Debug, Clone, Copy)]
enum End {
    First,
    Last,
}

/// What ties a member's fragments together, since their stored names may differ.
#[derive(Debug, Clone, Copy)]
struct MemberKey {
    /// `None` when the header marks it unknown, as a set written from stdin
    /// does on every fragment but the last.
    size: Option<u64>,
    coding: u64,
    encrypted: bool,
}

impl MemberKey {
    /// Whether `next` can continue a member with this key. An unknown size
    /// matches any size.
    fn continues_as(&self, next: &MemberKey) -> bool {
        let sizes_agree = match (self.size, next.size) {
            (Some(size), Some(next)) => size == next,
            _ => true,
        };
        sizes_agree && self.coding == next.coding && self.encrypted == next.encrypted
    }
}

struct Fragment {
    before: bool,
    after: bool,
    name: Vec<u8>,
    key: MemberKey,
}

/// The fragments of one member found so far, in volume order.
struct Chain {
    name: Vec<u8>,
    volume: usize,
    key: MemberKey,
    missing_start: bool,
    fragments: Vec<(usize, End)>,
}

impl Chain {
    fn new(volume: usize, fragment: &Fragment, missing_start: bool) -> Self {
        Self {
            name: fragment.name.clone(),
            volume,
            key: fragment.key,
            missing_start,
            fragments: Vec::new(),
        }
    }

    fn close(
        self,
        missing_end: bool,
        incomplete: &mut Vec<IncompleteMember>,
        drops: &mut Vec<(usize, End)>,
    ) {
        let missing = match (self.missing_start, missing_end) {
            (false, false) => return,
            (true, false) => MissingPart::Start,
            (false, true) => MissingPart::End,
            (true, true) => MissingPart::Both,
        };
        drops.extend(self.fragments);
        incomplete.push(IncompleteMember {
            name: self.name,
            volume: self.volume,
            missing,
        });
    }
}

/// A volume's first file if it continues a member, and its last if that runs on.
/// A lone file that does both is returned as the first.
fn split_ends(volume: &Archive) -> (Option<Fragment>, Option<Fragment>) {
    if !volume.is_volume() {
        return (None, None);
    }
    let edges = match volume {
        Archive::Rar13(archive) => edges(archive.entries.iter(), |entry| Fragment {
            before: entry.is_split_before(),
            after: entry.is_split_after(),
            name: entry.name.clone(),
            key: MemberKey {
                size: Some(u64::from(entry.header.unp_size)),
                coding: u64::from(entry.header.method),
                encrypted: entry.is_encrypted(),
            },
        }),
        Archive::Rar15To40(archive) => edges(archive.files(), |file| Fragment {
            before: file.is_split_before(),
            after: file.is_split_after(),
            name: file.name.clone(),
            key: MemberKey {
                size: file.known_unp_size(),
                coding: u64::from(file.method) | u64::from(file.unp_ver) << 8,
                encrypted: file.is_encrypted(),
            },
        }),
        Archive::Rar50Plus(archive) => edges(archive.files(), |file| Fragment {
            before: file.is_split_before(),
            after: file.is_split_after(),
            name: file.name.clone(),
            key: MemberKey {
                size: file.known_unpacked_size(),
                coding: file.compression_info,
                encrypted: file.encrypted,
            },
        }),
    };
    match edges {
        None => (None, None),
        Some((first, None)) if first.before => (Some(first), None),
        Some((only, None)) => (None, only.after.then_some(only)),
        Some((mut first, Some(last))) => {
            // Only a lone file can run on from the volume's start.
            first.after = false;
            (first.before.then_some(first), last.after.then_some(last))
        }
    }
}

/// A volume's first file and, when it has more than one, its last.
fn edges<'a, T: 'a>(
    mut files: impl Iterator<Item = &'a T>,
    describe: impl Fn(&'a T) -> Fragment,
) -> Option<(Fragment, Option<Fragment>)> {
    let first = describe(files.next()?);
    Some((first, files.last().map(describe)))
}

fn remove_file(volume: &mut Archive, end: End) {
    fn position<T>(items: &[T], is_file: impl Fn(&T) -> bool, end: End) -> Option<usize> {
        match end {
            End::First => items.iter().position(is_file),
            End::Last => items.iter().rposition(is_file),
        }
    }
    match volume {
        Archive::Rar13(archive) => {
            if let Some(index) = position(&archive.entries, |_| true, end) {
                archive.entries.remove(index);
            }
        }
        Archive::Rar15To40(archive) => {
            let is_file =
                |block: &crate::rar15_40::Block| matches!(block, crate::rar15_40::Block::File(_));
            if let Some(index) = position(&archive.blocks, is_file, end) {
                archive.blocks.remove(index);
            }
        }
        Archive::Rar50Plus(archive) => {
            let is_file =
                |block: &crate::rar50::Block| matches!(block, crate::rar50::Block::File(_));
            if let Some(index) = position(&archive.blocks, is_file, end) {
                archive.blocks.remove(index);
            }
        }
    }
}
