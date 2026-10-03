//! Several selected payloads decoded through one extraction session.

use crate::{Archive, ArchiveReadOptions, ExtractionDecision, Result, SharedBuffer};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

type Bytes = Arc<Mutex<Option<Vec<u8>>>>;

struct SelectedBuffer {
    first_position: usize,
    duplicates: Vec<usize>,
    bytes: Bytes,
}

struct ReadBatch {
    buffers: BTreeMap<usize, SelectedBuffer>,
    length: usize,
}

impl ReadBatch {
    fn new(indices: &[usize]) -> Self {
        let mut buffers = BTreeMap::<usize, SelectedBuffer>::new();
        for (position, &index) in indices.iter().enumerate() {
            buffers
                .entry(index)
                .and_modify(|buffer| buffer.duplicates.push(position))
                .or_insert_with(|| SelectedBuffer {
                    first_position: position,
                    duplicates: Vec::new(),
                    bytes: Arc::new(Mutex::new(None)),
                });
        }
        Self {
            buffers,
            length: indices.len(),
        }
    }

    fn contains(&self, index: usize) -> bool {
        self.buffers.contains_key(&index)
    }

    fn writer(&self, index: usize) -> Option<Box<dyn Write>> {
        let buffer = self.buffers.get(&index)?;
        *buffer
            .bytes
            .lock()
            .expect("member buffer mutex is not poisoned") = Some(Vec::new());
        Some(Box::new(SharedBuffer(Arc::clone(&buffer.bytes))))
    }

    fn finish(self) -> Vec<Option<Vec<u8>>> {
        let mut result = vec![None; self.length];
        for buffer in self.buffers.into_values() {
            if let Some(bytes) = buffer
                .bytes
                .lock()
                .expect("member buffer mutex is not poisoned")
                .take()
            {
                for position in buffer.duplicates {
                    result[position] = Some(bytes.clone());
                }
                // Unique selections transfer their output without a payload copy.
                result[buffer.first_position] = Some(bytes);
            }
        }
        result
    }
}

impl Archive {
    /// Whether archive or member headers declare solid decoding dependencies.
    /// This uses the same conservative policy as controlled extraction.
    pub fn is_solid(&self) -> bool {
        let main_solid = match self {
            Self::Rar13(archive) => archive.main.is_solid(),
            Self::Rar15To40(archive) => archive.main.is_solid(),
            Self::Rar50Plus(archive) => archive.main.is_solid(),
        };
        main_solid || self.member_refs().any(|member| member.is_solid())
    }

    /// Reads several members by archive-order index using one decoder session.
    /// See [`Self::read_members_at_with_options`] for selection and budget rules.
    pub fn read_members_at(
        &self,
        indices: &[usize],
        password: Option<&[u8]>,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        self.read_members_at_with_options(
            indices,
            ArchiveReadOptions::with_optional_password(password),
        )
    }

    /// Reads selected payloads in one pass, avoiding repeated solid-prefix decoding.
    ///
    /// Results follow the requested order, including duplicate indices. Missing
    /// members, directories and redirections return `None`. Each selected payload
    /// is decoded once; repeated results copy its verified bytes. Independent
    /// unselected payloads are skipped. Solid predecessors are decoded and
    /// verified once, even when their output is discarded.
    ///
    /// Output budgets are shared across this call and include all decoded bytes;
    /// returning another copy of a selected payload does not decode it again or
    /// consume logical output quota again. Result buffers are caller output, not
    /// decoder workspace. No buffers are returned if any selected payload or
    /// required predecessor fails. Cancellation is checked for empty selections.
    pub fn read_members_at_with_options(
        &self,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        options.check_cancelled()?;
        let batch = ReadBatch::new(indices);
        if indices.is_empty() {
            return Ok(batch.finish());
        }
        let last = self
            .member_refs()
            .enumerate()
            .filter(|(index, member)| {
                batch.contains(*index) && !member.is_directory() && !member.is_redirection()
            })
            .map(|(index, _)| index)
            .last();
        let Some(last) = last else {
            return Ok(batch.finish());
        };
        let solid = self.is_solid();
        let mut current = 0;
        self.extract_with_control(options, |member| {
            let index = current;
            current += 1;
            if index > last {
                return Ok(ExtractionDecision::Stop);
            }
            if member.meta.is_directory || member.meta.is_redirection {
                return Ok(ExtractionDecision::Skip);
            }
            if let Some(writer) = batch.writer(index) {
                return Ok(ExtractionDecision::Extract(writer));
            }
            Ok(if solid {
                ExtractionDecision::Extract(Box::new(std::io::sink()))
            } else {
                ExtractionDecision::Skip
            })
        })?;
        Ok(batch.finish())
    }
}

// Redirections have logical indices but do not open volume extraction writers.
// Continuation headers share the logical index of their first fragment.
pub(crate) fn volume_output_indices(archives: &[Archive]) -> impl Iterator<Item = usize> + '_ {
    archives
        .iter()
        .flat_map(Archive::member_refs)
        .filter(|member| !member.is_split_before())
        .enumerate()
        .filter_map(|(index, member)| (!member.is_redirection()).then_some(index))
}

/// Reads several logical volume members in one traversal of the volume set.
/// See [`read_volume_members_at_with_options`] for budget and selection rules.
pub fn read_volume_members_at(
    archives: &[Archive],
    indices: &[usize],
    password: Option<&[u8]>,
) -> Result<Vec<Option<Vec<u8>>>> {
    read_volume_members_at_with_options(
        archives,
        indices,
        ArchiveReadOptions::with_optional_password(password),
    )
}

/// Reads selected logical volume members, preserving order and duplicate indices.
///
/// Missing members, directories and redirections return `None`. The current
/// volume traversal decodes and verifies the whole set, including unselected
/// payloads and empty selections; discarded output counts against shared quotas.
/// Each payload is decoded once. Copies returned for repeated indices do not
/// consume additional logical output quota. No result buffers escape on failure.
pub fn read_volume_members_at_with_options(
    archives: &[Archive],
    indices: &[usize],
    options: ArchiveReadOptions<'_>,
) -> Result<Vec<Option<Vec<u8>>>> {
    options.check_cancelled()?;
    let batch = ReadBatch::new(indices);
    let mut output_indices = volume_output_indices(archives);
    crate::extract_volumes_to_with_options(archives, options, |meta| {
        let index = output_indices.next();
        if !meta.is_directory {
            if let Some(writer) = index.and_then(|index| batch.writer(index)) {
                return Ok(writer);
            }
        }
        Ok(Box::new(std::io::sink()))
    })?;
    Ok(batch.finish())
}
