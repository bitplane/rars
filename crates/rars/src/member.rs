//! Borrowed member traversal without copying names or format-specific records.

use crate::{rar13, rar15_40, rar50, Archive, ArchiveMember, Result};
use std::borrow::Cow;
use std::collections::HashMap;

/// A member header borrowed from its archive, including all format metadata.
///
/// Use [`Self::to_owned`] when the metadata must outlive the archive borrow.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ArchiveMemberRef<'a> {
    /// RAR 1.3/1.4 member.
    Rar13(&'a rar13::Entry),
    /// RAR 1.5 through 4.x member.
    Rar15To40(&'a rar15_40::FileHeader),
    /// RAR 5.0 or later member.
    Rar50Plus(&'a rar50::FileHeader),
}

impl<'a> ArchiveMemberRef<'a> {
    /// Exact name bytes, without copying or interpreting legacy encodings.
    pub fn name_bytes(self) -> &'a [u8] {
        match self {
            Self::Rar13(entry) => &entry.name,
            Self::Rar15To40(file) => &file.name,
            Self::Rar50Plus(file) => &file.name,
        }
    }

    /// Whether the member is a directory.
    pub fn is_directory(self) -> bool {
        match self {
            Self::Rar13(entry) => entry.is_directory(),
            Self::Rar15To40(file) => file.is_directory(),
            Self::Rar50Plus(file) => file.is_directory(),
        }
    }

    /// Whether the member carries a RAR5 redirection record.
    pub fn is_redirection(self) -> bool {
        matches!(self, Self::Rar50Plus(file) if file.is_redirection())
    }

    /// Whether this member declares a dependency on preceding decoded history.
    /// RAR 1.3 has no member flag; consult its archive main header.
    pub fn is_solid(self) -> bool {
        match self {
            Self::Rar13(_) => false,
            Self::Rar15To40(file) => file.is_solid(),
            Self::Rar50Plus(file) => file.compression_info & 0x40 != 0,
        }
    }

    /// Whether the format supplied Unicode rather than unspecified legacy bytes.
    pub fn name_is_unicode(self) -> bool {
        match self {
            Self::Rar13(_) => false,
            Self::Rar15To40(file) => file.unicode_name.is_some(),
            Self::Rar50Plus(_) => true,
        }
    }

    /// Display/destination name interpretation; stored identity remains unchanged.
    pub fn decoded_name(
        self,
        encoding: Option<crate::filename::LegacyNameEncoding>,
    ) -> Result<Cow<'a, [u8]>> {
        crate::filename::decoded_name(self.name_bytes(), self.name_is_unicode(), encoding)
    }

    /// Copies this member's common and format-specific metadata.
    pub fn to_owned(&self) -> ArchiveMember {
        match *self {
            Self::Rar13(entry) => crate::rar13_member(entry),
            Self::Rar15To40(file) => crate::rar15_40_member(file),
            Self::Rar50Plus(file) => crate::rar50_member(file),
        }
    }
}

/// Lazy borrowed traversal returned by [`Archive::member_refs`].
#[derive(Debug, Clone)]
pub struct ArchiveMemberRefs<'a> {
    inner: MemberRefsInner<'a>,
}

#[derive(Debug, Clone)]
enum MemberRefsInner<'a> {
    Rar13(std::slice::Iter<'a, rar13::Entry>),
    Rar15To40(std::slice::Iter<'a, rar15_40::Block>),
    Rar50Plus(std::slice::Iter<'a, rar50::Block>),
}

impl<'a> ArchiveMemberRefs<'a> {
    pub(crate) fn new(archive: &'a Archive) -> Self {
        let inner = match archive {
            Archive::Rar13(archive) => MemberRefsInner::Rar13(archive.entries.iter()),
            Archive::Rar15To40(archive) => MemberRefsInner::Rar15To40(archive.blocks.iter()),
            Archive::Rar50Plus(archive) => MemberRefsInner::Rar50Plus(archive.blocks.iter()),
        };
        Self { inner }
    }
}

impl<'a> Iterator for ArchiveMemberRefs<'a> {
    type Item = ArchiveMemberRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            MemberRefsInner::Rar13(entries) => entries.next().map(ArchiveMemberRef::Rar13),
            MemberRefsInner::Rar15To40(blocks) => blocks.find_map(|block| match block {
                rar15_40::Block::File(file) => Some(ArchiveMemberRef::Rar15To40(file)),
                _ => None,
            }),
            MemberRefsInner::Rar50Plus(blocks) => blocks.find_map(|block| match block {
                rar50::Block::File(file) => Some(ArchiveMemberRef::Rar50Plus(file)),
                _ => None,
            }),
        }
    }
}

/// An optional index borrowing immutable archive headers and name bytes.
///
/// Construction traverses headers once and allocates caller-owned index storage.
/// Indexed metadata lookup does not allocate or traverse preceding members.
/// Duplicate entries retain their archive-order indices. Name lookup selects the
/// last entry, while payload lookup excludes directories and redirections.
/// Payload decoding still uses the archive's extraction policies.
#[derive(Debug)]
pub struct ArchiveIndex<'a> {
    members: Vec<ArchiveMemberRef<'a>>,
    names: HashMap<&'a [u8], NameIndices>,
}

#[derive(Debug, Default)]
struct NameIndices {
    last: usize,
    payload: Option<usize>,
}

impl<'a> ArchiveIndex<'a> {
    pub(crate) fn new(archive: &'a Archive) -> Self {
        let members: Vec<_> = archive.member_refs().collect();
        let mut names: HashMap<&[u8], NameIndices> = HashMap::new();
        for (index, member) in members.iter().enumerate() {
            let indices = names.entry(member.name_bytes()).or_default();
            indices.last = index;
            if !member.is_directory() && !member.is_redirection() {
                indices.payload = Some(index);
            }
        }
        Self { members, names }
    }

    /// Number of members, including directories and redirections.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the archive contains no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Borrows metadata for an archive-order index without copying it.
    pub fn get(&self, index: usize) -> Option<ArchiveMemberRef<'a>> {
        self.members.get(index).copied()
    }

    /// Archive-order index of the last entry with this exact stored name.
    pub fn index_of(&self, name: &[u8]) -> Option<usize> {
        self.names.get(name).map(|indices| indices.last)
    }

    /// Last payload index, matching [`Archive::read_member`] selection.
    /// A later directory or redirection with the same name does not hide a file.
    pub fn payload_index_of(&self, name: &[u8]) -> Option<usize> {
        self.names.get(name).and_then(|indices| indices.payload)
    }

    /// All borrowed member headers in archive order.
    pub fn members(&self) -> &[ArchiveMemberRef<'a>] {
        &self.members
    }
}

#[cfg(all(test, feature = "write"))]
mod tests {
    use crate::{ArchiveReader, ArchiveVersion, Builder};

    #[test]
    fn borrowed_members_preserve_metadata_and_archive_order_across_families() {
        for version in ArchiveVersion::ALL {
            let mut builder = Builder::new(version).store(true);
            builder.add_directory(b"dir".to_vec(), None, None).unwrap();
            builder
                .add_bytes(b"dir/file".to_vec(), b"payload".to_vec(), None, None)
                .unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let members: Vec<_> = archive.member_refs().collect();
            assert_eq!(members.len(), 2, "{version}");
            assert!(members[0].is_directory());
            assert!(!members[1].is_directory());
            assert_eq!(members[1].name_bytes(), b"dir/file");
            for (borrowed, owned) in members.iter().zip(archive.members()) {
                assert_eq!(borrowed.to_owned(), owned);
                assert_eq!(borrowed.is_solid(), owned.is_solid());
                assert_eq!(borrowed.name_is_unicode(), owned.name_is_unicode());
                assert_eq!(borrowed.is_redirection(), owned.meta.is_redirection);
                assert_eq!(
                    borrowed.decoded_name(None).unwrap().as_ref(),
                    owned.meta.name
                );
                assert!(std::ptr::eq(
                    borrowed.name_bytes().as_ptr(),
                    archive
                        .member_refs()
                        .find(|m| m.name_bytes() == borrowed.name_bytes())
                        .unwrap()
                        .name_bytes()
                        .as_ptr(),
                ));
            }
            let mut owned = archive.members();
            assert_eq!(owned.nth(1).unwrap().meta.name, b"dir/file");
            assert_eq!(owned.next(), None);
            assert_eq!(
                archive.read_member_at(1, None).unwrap().unwrap(),
                b"payload"
            );
        }
    }

    #[test]
    fn member_index_preserves_duplicates_and_distinguishes_payload_lookup() {
        for version in ArchiveVersion::ALL {
            let mut builder = Builder::new(version)
                .store(true)
                .allow_duplicate_names(true);
            for data in [b"first".as_slice(), b"second"] {
                builder
                    .add_bytes(b"same".to_vec(), data.to_vec(), None, None)
                    .unwrap();
            }
            builder.add_directory(b"same".to_vec(), None, None).unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let index = archive.index();
            assert_eq!(index.len(), 3, "{version}");
            assert!(!index.is_empty());
            assert_eq!(index.index_of(b"same"), Some(2));
            assert_eq!(index.payload_index_of(b"same"), Some(1));
            assert_eq!(index.index_of(b"missing"), None);
            assert_eq!(index.payload_index_of(b"missing"), None);
            assert_eq!(index.get(0).unwrap().to_owned().meta.unpacked_size, 5);
            assert_eq!(index.get(1).unwrap().to_owned().meta.unpacked_size, 6);
            assert!(index.get(2).unwrap().is_directory());
            assert!(index.get(3).is_none());
            assert_eq!(index.members().len(), 3);
            assert_eq!(
                archive.read_member(b"same", None).unwrap().unwrap(),
                b"second"
            );
        }
    }
}
