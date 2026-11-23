//! Assembling a RAR 5 archive from prepared payloads.
//!
//! Native member spools use temporary files; bare-WASM spools retain bytes in
//! memory. Compression may load whole members; headers also allocate memory.
//! Service payloads borrow input and are encrypted in chunks during emission.
//! Quick-open data uses a quota-controlled spool. Members go out in order as
//! their windows finish, unless recovery, or quick open on a stream output,
//! needs every block length before the main header, in which case they are
//! held until the last. Quick open on a seekable output reserves the main
//! header's offset to its block and patches it at the end. On a seekable
//! output, a large non-solid member goes out as it is packed, encrypted on the
//! way if it has a password, behind a header patched once it is done, or
//! stored over its attempt when packing does not pay. The workspace admission
//! budget is not an aggregate RAM or disk quota.
//!
//! Stored payloads are reread and verified during emission, or, when the output
//! can seek and every member is stored, read once behind a header patched
//! with the checksums of what was copied. Recovery requires
//! a further pass over the preceding archive bytes, mirrored into a spool.

use super::compress::{self, ClosedMember, CompressPlan, CompressedMember, Handed};
#[cfg(test)]
use super::headers::write_vint;
use super::headers::{
    block_header_image, encrypted_header_block, encrypted_main_header_block, file_specific,
    fresh_iv, header_encryption_keys, header_encryption_password, prepared_header_image,
    repeated_header_image, stored_file_specific, write_end_header, write_extra_record,
    write_file_encryption_record, write_hash_record_with_value, write_head_crypt,
    write_main_header, HeaderEncryptionKeys, PreparedHeader, WriteKeys,
};
use super::headers::{prepared_header_image_at_least, reserved_header_image};
use super::layout::{recovery_covers, resolve_layout, settle_layout, LayoutInputs};
use super::{encrypt_reader_to, ArchiveEntry};
use crate::crypto::rar50::Rar50Keys;
use crate::detect::RAR50_SIGNATURE;
use crate::rar50::{
    FHEXTRA_SUBDATA, HEAD_END, HEAD_FILE, HEAD_SERVICE, HFL_DATA, HFL_EXTRA, MHFL_RECOVERY,
    MHFL_SOLID,
};
#[cfg(feature = "recovery")]
use crate::recovery::rar5::{
    choose_recovery_memory_mode, plan_inline_recovery, streamed_recovery_with_allowance,
    ReadWriteSeek,
};
use crate::streaming::preparation::{Bytes, Owned, Records};
use crate::streaming::Spool;
use crate::write_progress::{check_cancelled, CancellableIo, ProgressReporter, WorkTracker};
use crate::write_stream::{patch_header, CallerOutput, CancellableOutput};
use crate::{Error, Result, WriterResources};
use std::io::{Read, Seek, Write};

pub(super) struct EnginePlan<'a> {
    pub(super) compress: CompressPlan,
    pub(super) recovery_percent: Option<u64>,
    pub(super) header_encrypted: bool,
    pub(super) header_password: Option<&'a [u8]>,
    pub(super) archive_comment: Option<ArchiveCommentPlan<'a>>,
    pub(super) archive_metadata: Option<crate::rar50::ArchiveMetadataEntry<'a>>,
    pub(super) metadata_record: Option<&'a crate::rar50::ArchiveMetadataRecord>,
    pub(super) locked: bool,
    pub(super) quick_open: bool,
    pub(super) progress: Option<ProgressReporter<'a>>,
}

pub(super) enum ArchiveCommentPlan<'a> {
    Plain(&'a [u8]),
    Encrypted { data: &'a [u8], password: &'a [u8] },
}

/// A block with its framing settled: the header bytes are final and the
/// payload only has to be copied.
struct PreparedBlock<'a> {
    header: PreparedHeader,
    payload: Payload<'a>,
    payload_len: u64,
    /// Quick-open repeats the headers of members and plain comments so a
    /// reader can list an archive without walking it.
    quick_open_cached: bool,
    /// Index into the caller's entries; names are cloned only on error.
    entry_index: Option<usize>,
    /// The header's checksums wait for the copy, so it is rewritten after it.
    patch: Option<MemberHeader>,
    /// Record offset and distance, so a patched header reaches quick-open too.
    quick_open_record: Option<(u64, u64)>,
}

impl PreparedBlock<'_> {
    fn len(&self) -> Result<u64> {
        (self.header.len() as u64)
            .checked_add(self.payload_len)
            .ok_or(Error::InvalidArgument("RAR 5 archive block size overflows"))
    }
}

enum Payload<'a> {
    /// Comments and services remain owned by the caller or builder.
    Borrowed(&'a [u8]),
    /// Copied straight from the source, which is re-read at write time.
    Stored(PreparedSource),
    Packed(Spool),
    /// Encrypted on the way out, so the ciphertext is never stored anywhere.
    Encrypted {
        plain: Owned<PlainPayload<'a>>,
        keys: Rar50Keys,
        iv: [u8; 16],
    },
}

enum PlainPayload<'a> {
    Borrowed(&'a [u8]),
    Stored(PreparedSource),
    Packed(Spool),
}

// Member payloads cannot borrow comment/service bytes. Keeping their two
// forms distinct avoids an impossible borrowed arm during plain emission.
enum MemberPlainPayload {
    Stored(PreparedSource),
    Packed(Spool),
}

impl From<MemberPlainPayload> for PlainPayload<'_> {
    fn from(member: MemberPlainPayload) -> Self {
        match member {
            MemberPlainPayload::Stored(source) => Self::Stored(source),
            MemberPlainPayload::Packed(packed) => Self::Packed(packed),
        }
    }
}

impl From<MemberPlainPayload> for Payload<'_> {
    fn from(member: MemberPlainPayload) -> Self {
        match member {
            MemberPlainPayload::Stored(source) => Self::Stored(source),
            MemberPlainPayload::Packed(packed) => Self::Packed(packed),
        }
    }
}

// A reopenable source is not a snapshot. Keep the size and integrity used by
// the header, and verify the actual emission read before reporting success.
struct PreparedSource {
    source: crate::EntrySource,
    len: u64,
    crc32: u32,
    /// Present only when the archive stores BLAKE2sp hashes.
    hash: Option<[u8; 32]>,
    /// Not hashed yet: the copy's checksums go into a patched header.
    hashed_on_copy: bool,
}

impl PreparedSource {
    fn new(source: &crate::EntrySource, member: &CompressedMember, hashed_on_copy: bool) -> Self {
        Self {
            source: source.clone(),
            len: member.input_size,
            crc32: member.crc32,
            hash: member.hash,
            hashed_on_copy,
        }
    }

    fn open<'w, 'p>(&self, work: Option<&'w WorkTracker<'p>>) -> Result<CheckedReader<'w, 'p>> {
        Ok(CheckedReader {
            reader: self.source.open()?,
            integrity: self.checksum_sink(),
            work,
        })
    }

    /// A sink computing the checksums this member's header carries.
    fn checksum_sink(&self) -> ChecksumSink {
        ChecksumSink::new(self.hash.is_some())
    }

    /// The copy's checksums for a member hashed on its copy; otherwise
    /// checks them against the ones its header already carries.
    fn finish_checksums(&self, integrity: ChecksumSink) -> Result<Option<ChecksumSink>> {
        if self.hashed_on_copy {
            return Ok(Some(integrity));
        }
        self.verify(integrity)?;
        Ok(None)
    }

    fn verify(&self, integrity: ChecksumSink) -> Result<()> {
        let (crc32, hash) = integrity.finish();
        if crc32 != self.crc32 || hash != self.hash {
            return Err(Error::SourceChanged(
                "entry source contents changed while writing",
            ));
        }
        Ok(())
    }
}

struct CheckedReader<'w, 'p> {
    reader: Box<dyn crate::EntryReader>,
    integrity: ChecksumSink,
    /// Advanced as a member hashed on its copy is read.
    work: Option<&'w WorkTracker<'p>>,
}

impl Read for CheckedReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buffer)?;
        self.integrity.write_all(&buffer[..read])?;
        if let Some(work) = self.work {
            if !work.advance(read as u64) {
                return Err(std::io::Error::other(Error::Cancelled));
            }
        }
        Ok(read)
    }
}

impl CheckedReader<'_, '_> {
    fn finish(mut self, source: &PreparedSource, observed: u64) -> Result<Option<ChecksumSink>> {
        crate::write_stream::check_source_length(
            &mut *self.reader,
            observed,
            source.len,
            "entry source size changed while writing",
        )?;
        source.finish_checksums(self.integrity)
    }
}

// Both archive and volume emission report and account for one aggregate input
// length. Caller-provided source lengths need not fit that sum even when each
// length fits a member header. Reject overflow before any payload read.
fn total_input_size(entries: &[ArchiveEntry]) -> Result<u64> {
    entries.iter().try_fold(0u64, |total, entry| {
        let length = entry
            .source
            .len()
            .map_err(|error| member_error(error, &entry.name, "preparing"))?;
        total.checked_add(length).ok_or_else(|| {
            member_error(
                Error::InvalidArgument("RAR 5 writer total input size overflows"),
                &entry.name,
                "preparing",
            )
        })
    })
}

pub(super) fn write_archive<'a>(
    entries: &'a [ArchiveEntry],
    plan: EnginePlan<'a>,
    resources: &WriterResources,
    output: CallerOutput<'_>,
) -> Result<()> {
    let mut sink = output.cancellable(plan.progress);
    // A seekable archive lets stored members be read once and their headers
    // patched. Every member is stored, so none is read before it is copied.
    let hash_on_copy = sink.can_seek() && plan.compress.method == 0;
    // Members go out as their windows finish unless the main header has to
    // locate blocks after them and cannot be patched. Stored members hashed on
    // their copy already go out in one pass.
    let in_order =
        !hash_on_copy && plan.recovery_percent.is_none() && (!plan.quick_open || sink.can_seek());
    // The main header goes out first and its quick-open offset is patched.
    let quick_open_patched_in = plan.quick_open && in_order;
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let mut write_keys = WriteKeys::default();
    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            plan.header_password
                .into_iter()
                .chain(entries.iter().filter_map(|entry| entry.password.as_deref())),
        )?;
        Some(header_encryption_keys(&mut write_keys, password)?)
    } else {
        None
    };

    let mut sources = Records::new(entries.len(), resources)?;
    for entry in entries {
        sources.push(entry.source.clone())?;
    }
    let total_input = total_input_size(entries)?;
    let total_entries = entries.len();
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationStarted {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
    let work = crate::write_progress::WorkTracker::new(
        plan.progress,
        crate::WriteOperation::Compression,
        total_input,
    );

    let head_crypt = match &header_keys {
        Some(keys) => {
            let mut block = Bytes::new(resources);
            write_head_crypt(&mut block, keys, resources)?;
            block
        }
        None => Bytes::new(resources),
    };
    let mut main_flags = if plan.locked {
        crate::rar50::MHFL_LOCKED
    } else {
        0
    };
    if plan.compress.solid {
        main_flags |= MHFL_SOLID;
    }
    if plan.recovery_percent.is_some() {
        main_flags |= MHFL_RECOVERY;
    }
    let layout_inputs_at_width =
        |body_len, quick_open_payload_len, quick_open_width| LayoutInputs {
            header_encrypted: plan.header_encrypted,
            head_crypt_len: head_crypt.len() as u64,
            main_flags,
            volume_number: None,
            archive_metadata: plan.archive_metadata,
            metadata_record: plan.metadata_record,
            body_len,
            quick_open_payload_len,
            quick_open_width,
            recovery_percent: plan.recovery_percent,
        };
    // Settled before any member, so a seekable and a stream output agree.
    let quick_open_width = if plan.quick_open {
        // A vint takes at most ten bytes.
        let widest_main = resolve_layout(&layout_inputs_at_width(0, Some(0), 10), resources)?;
        widest_quick_open_offset(entries, &plan, widest_main.main_header_len)
    } else {
        0
    };
    let layout_inputs = |body_len, quick_open_payload_len| {
        layout_inputs_at_width(body_len, quick_open_payload_len, quick_open_width)
    };

    // Only mirror the archive when a recovery record has to read it back.
    let mut mirror = match plan.recovery_percent {
        Some(_) => Some(Spool::create(resources)?),
        None => None,
    };
    // Members hashed on their copy report it here, as compression skipped them.
    let copy_work = WorkTracker::new(
        plan.progress,
        crate::WriteOperation::Emission,
        if hash_on_copy { total_input } else { 0 },
    );
    let mut quick_open_payload = None;
    let mut quick_open_patched = false;
    let mut emit = |block: PreparedBlock<'_>,
                    sink: &mut CancellableOutput<'_, '_>,
                    mirror: &mut Option<Spool>,
                    quick_open_payload: &mut Option<(PreparedHeader, Spool)>,
                    written: &mut Option<WrittenHeaders>|
     -> Result<()> {
        let entry_index = block.entry_index;
        if let Some(written) = written.as_mut().filter(|_| block.quick_open_cached) {
            debug_assert!(
                block.patch.is_none(),
                "a member hashed on its copy is held, not recorded"
            );
            let at = sink
                .as_seekable()
                .expect("headers are recorded only on a seekable output")
                .stream_position()?;
            written.record(at, &block.header)?;
        }
        let result = emit_block(
            block,
            entries,
            sink,
            mirror,
            quick_open_payload.as_mut().map(|(_, payload)| payload),
            header_keys.as_ref(),
            resources,
            plan.progress,
            &copy_work,
        );
        quick_open_patched |= result.as_ref().is_ok_and(|patched| *patched);
        result.map(|_| ()).map_err(|error| match entry_index {
            Some(index) => member_error(error, &entries[index].name, "writing"),
            None => error,
        })
    };

    let mut leading = Records::<PreparedBlock>::new(2, resources)?;
    leading.push(producer_block(header_keys.as_ref(), resources)?)?;
    if let Some(comment) = &plan.archive_comment {
        leading.push(prepare_comment(
            comment,
            &mut write_keys,
            header_keys.as_ref(),
            resources,
        )?)?;
    }
    // Drawn here whether the main header goes out before the members or after,
    // so a seekable and a stream output draw in the same order.
    let main_iv = header_keys.as_ref().map(|_| fresh_iv()).transpose()?;
    // Written in front of the first member, so a write that stops before any
    // member is ready leaves the output untouched. A caller's output may
    // already hold a prefix, so where the archive starts is returned.
    let begin = |sink: &mut CancellableOutput<'_, '_>, mirror: &mut Option<Spool>| {
        report_emission(plan.progress, true);
        let quick_open = quick_open_patched_in.then_some(0);
        let layout = resolve_layout(&layout_inputs(0, quick_open), resources)?;
        let archive_at = sink
            .as_seekable()
            .map(|output| output.stream_position())
            .transpose()?;
        write_archive_head(
            sink,
            main_iv,
            mirror,
            &head_crypt,
            &layout.main_extra,
            layout.main_header_len,
            main_flags,
            header_keys.as_ref(),
            resources,
        )?;
        Ok::<_, Error>(archive_at)
    };
    // Entries and their owned service vectors contain records larger than a
    // byte in disjoint live storage, so their combined count fits usize.
    let block_count = entries.iter().fold(leading.len(), |total, entry| {
        total + 1 + entry.services.len()
    });
    let mut written = quick_open_patched_in
        .then(|| WrittenHeaders::new(block_count, resources))
        .transpose()?;
    let mut archive_at = None;
    // Everything between the main header and the quick-open block, in order,
    // held only while the main header waits for its length.
    let (mut held, mut leading) = if in_order {
        (None, Some(leading))
    } else {
        let mut held = Records::<PreparedBlock>::new(block_count, resources)?;
        for block in leading {
            held.push(block)?;
        }
        (Some(held), None)
    };

    // Large members go out as they are packed, behind a header patched once
    // they are done, when the archive can seek and nothing is held. Only a
    // member that would be stored rather than grow does: its payload never
    // outgrows its declared size, padded to the cipher block if encrypted,
    // which sizes the header's reserved field.
    let straight_above = sink.stream_above.filter(|_| {
        in_order
            && sink.can_seek()
            && !plan.compress.solid
            && !matches!(
                plan.compress.filter_policy,
                super::FilterPolicy::Explicit(_)
            )
    });
    let straight = |_: usize, size: u64| straight_above.is_some_and(|above| size > above);
    let mut in_place: Option<InPlace> = None;
    compress::compress_members_in_order(
        &sources,
        &plan.compress,
        resources,
        &MemberProgress {
            entries,
            work: &work,
        },
        &|index, error| member_error(error, &entries[index].name, "compressing"),
        hash_on_copy,
        &straight,
        &mut |index, handed| {
            check_cancelled(plan.progress)?;
            let entry = &entries[index];
            // A member and its services are all prepared before any goes out.
            let mut blocks = Records::<PreparedBlock>::new(1 + entry.services.len(), resources)?;
            let mut opening = None;
            match handed {
                Handed::Packed(bytes) => {
                    let member = in_place.as_mut().expect("packed bytes follow an opening");
                    return member
                        .write(bytes, &mut sink)
                        .map_err(|error| member_error(error, &entry.name, "writing"));
                }
                Handed::Opening { input_size } => opening = Some(input_size),
                Handed::Member(member) => {
                    let block = prepare_member(
                        entry,
                        member,
                        &plan,
                        hash_on_copy,
                        None,
                        &mut write_keys,
                        header_keys.as_ref(),
                        resources,
                    )
                    .map_err(|error| member_error(error, &entry.name, "preparing"))?;
                    blocks.push(block)?;
                }
                Handed::Closed(closed) => {
                    let member = in_place.take().expect("a member closes after it opens");
                    if closed.store {
                        // Stored, the member goes over the attempt, which it
                        // is at least as long as.
                        let block = prepare_member(
                            entry,
                            closed.stored(resources)?,
                            &plan,
                            false,
                            Some(&member),
                            &mut write_keys,
                            header_keys.as_ref(),
                            resources,
                        )
                        .map_err(|error| member_error(error, &entry.name, "preparing"))?;
                        blocks.push(block)?;
                    }
                    let header_at = member.header_at;
                    let patched = member
                        .close(entry, &closed, &mut sink, header_keys.as_ref(), resources)
                        .map_err(|error| member_error(error, &entry.name, "writing"))?;
                    if let (Some(written), Some(header)) = (written.as_mut(), patched) {
                        written.record(header_at, &header)?;
                    }
                }
            }
            if opening.is_none() {
                for service in &entry.services {
                    let block =
                        prepare_service(service, &mut write_keys, header_keys.as_ref(), resources)
                            .map_err(|error| {
                                member_error(error, &entry.name, "preparing service")
                            })?;
                    blocks.push(block)?;
                }
            }
            if held.is_none() {
                if let Some(leading) = leading.take() {
                    archive_at = begin(&mut sink, &mut mirror)?;
                    for block in leading {
                        emit(
                            block,
                            &mut sink,
                            &mut mirror,
                            &mut quick_open_payload,
                            &mut written,
                        )?;
                    }
                }
            }
            if let Some(input_size) = opening {
                let opened = InPlace::open(
                    entry,
                    input_size,
                    &plan,
                    &mut sink,
                    &mut write_keys,
                    header_keys.as_ref(),
                    resources,
                );
                in_place =
                    Some(opened.map_err(|error| member_error(error, &entry.name, "writing"))?);
            }
            for mut block in blocks {
                block.entry_index = Some(index);
                match held.as_mut() {
                    Some(held) => held.push(block)?,
                    None => emit(
                        block,
                        &mut sink,
                        &mut mirror,
                        &mut quick_open_payload,
                        &mut written,
                    )?,
                }
            }
            Ok(())
        },
    )?;
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationFinished {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
    // An archive without members.
    if let Some(leading) = leading {
        archive_at = begin(&mut sink, &mut mirror)?;
        for block in leading {
            emit(
                block,
                &mut sink,
                &mut mirror,
                &mut quick_open_payload,
                &mut written,
            )?;
        }
    }

    if let Some(written) = written.take() {
        let output = sink
            .as_seekable()
            .expect("headers are recorded only on a seekable output");
        let quick_open_at = output.stream_position()?;
        let (payload, checksum) = written.into_payload(quick_open_at, resources)?;
        let main_at = archive_at.expect("a seekable archive knows where it starts")
            + (RAR50_SIGNATURE.len() + head_crypt.len()) as u64;
        let main_len = resolve_layout(&layout_inputs(0, Some(0)), resources)?.main_header_len;
        let body_len = quick_open_at - main_at - main_len;
        let resolved = resolve_layout(&layout_inputs(body_len, Some(payload.len())), resources)?;
        let main = main_header_block(
            main_iv,
            &resolved.main_extra,
            main_flags,
            header_keys.as_ref(),
            resources,
        )?;
        patch_header(
            output,
            main_at,
            main_len,
            &main,
            Error::InvalidArgument("RAR 5 quick-open offset outgrew its reserved width"),
        )?;
        let header = stored_service_header(
            b"QO",
            payload.len(),
            checksum,
            &[],
            header_keys.as_ref(),
            resources,
        )?;
        quick_open_payload = Some((header, payload));
    }

    let mut layout = None;
    if let Some(mut blocks) = held {
        let body_len = blocks.iter().try_fold(0u64, |total, block| {
            total
                .checked_add(block.len()?)
                .ok_or(Error::InvalidArgument("RAR 5 archive body size overflows"))
        })?;

        // Quick-open stores how far back each cached header sits from the
        // quick-open block itself. Both move together when the prefix grows, so
        // the distances only need positions within the body.
        if plan.quick_open {
            let mut payload = Spool::create(resources)?;
            let mut checksum = crate::crc32::Crc32::new();
            let mut offset = 0u64;
            for block in blocks.iter_mut() {
                check_cancelled(plan.progress)?;
                if block.quick_open_cached {
                    let distance = body_len - offset;
                    if block.patch.is_some() {
                        block.quick_open_record = Some((payload.len(), distance));
                    }
                    append_quick_open_entry(&mut payload, &mut checksum, distance, &block.header)?;
                }
                offset += block.len()?;
            }
            let payload_len = payload.len();
            let header = stored_service_header(
                b"QO",
                payload_len,
                checksum.finish(),
                &[],
                header_keys.as_ref(),
                resources,
            )?;
            payload.park();
            quick_open_payload = Some((header, payload));
        }

        let resolved = resolve_layout(
            &layout_inputs(
                body_len,
                quick_open_payload
                    .as_ref()
                    .map(|(_, payload)| payload.len()),
            ),
            resources,
        )?;
        report_emission(plan.progress, true);
        write_archive_head(
            &mut sink,
            main_iv,
            &mut mirror,
            &head_crypt,
            &resolved.main_extra,
            resolved.main_header_len,
            main_flags,
            header_keys.as_ref(),
            resources,
        )?;
        for block in blocks {
            emit(
                block,
                &mut sink,
                &mut mirror,
                &mut quick_open_payload,
                &mut written,
            )?;
        }
        layout = Some(resolved);
    }

    if let Some((prepared, mut payload)) = quick_open_payload {
        let patched = if quick_open_patched {
            let payload_len = payload.len();
            let mut checksum = ChecksumSink::new(false);
            payload.copy_to(&mut checksum)?;
            let (specific, extra) =
                stored_service_parts(b"QO", payload_len, checksum.crc.finish(), &[], resources)?;
            Some(repeated_header_image(
                &prepared,
                HEAD_SERVICE,
                HFL_EXTRA | HFL_DATA,
                Some(payload_len),
                &specific,
                &extra,
                header_keys.as_ref(),
                resources,
            )?)
        } else {
            None
        };
        let mut tee = Tee {
            output: sink.writer(),
            mirror: mirror.as_mut().map(|spool| spool as &mut dyn Write),
        };
        tee.write_all(patched.as_deref().unwrap_or(&prepared))?;
        write_payload(
            Payload::Packed(payload),
            &mut tee,
            resources,
            plan.progress,
            None,
        )?;
    }

    let output = sink.writer();
    if let Some(recovery_percent) = plan.recovery_percent {
        let mirror = mirror.as_mut().expect("recovery mirrors the archive");
        let layout = layout
            .as_ref()
            .expect("recovery holds members for the layout");
        // The recovery block has to start exactly where the locator in the
        // main header says it does.
        debug_assert_eq!(layout.recovery_prefix_len, Some(mirror.len()));
        debug_assert_eq!(
            layout.recovery_offset,
            Some(mirror.len() - RAR50_SIGNATURE.len() as u64 - head_crypt.len() as u64),
            "recovery record is not where the locator points"
        );
        write_recovery_service(
            recovery_percent,
            mirror,
            header_keys.as_ref(),
            resources,
            plan.progress,
            output,
        )?;
    }

    match &header_keys {
        Some(keys) => output.write_all(&encrypted_header_block(
            &keys.keys,
            HEAD_END,
            0,
            None,
            &super::end_header_specific(0),
            &[],
            &[],
            resources,
        )?)?,
        None => {
            let mut end = Bytes::new(resources);
            write_end_header(&mut end, 0, resources)?;
            output.write_all(&end)?;
        }
    }
    check_cancelled(plan.progress)?;
    report_emission(plan.progress, false);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_archive_head(
    sink: &mut CancellableOutput<'_, '_>,
    main_iv: Option<[u8; 16]>,
    mirror: &mut Option<Spool>,
    head_crypt: &[u8],
    main_extra: &[u8],
    main_header_len: u64,
    main_flags: u64,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<()> {
    let main = main_header_block(main_iv, main_extra, main_flags, header_keys, resources)?;
    // The layout predicted this before any of it existed. If the
    // prediction is off, every offset in the locator is off with it.
    debug_assert_eq!(
        main.len() as u64,
        main_header_len,
        "main header size differs from the size its layout was built on"
    );
    let mut tee = Tee {
        output: sink.writer(),
        mirror: mirror.as_mut().map(|spool| spool as &mut dyn Write),
    };
    tee.write_all(RAR50_SIGNATURE)?;
    tee.write_all(head_crypt)?;
    tee.write_all(&main)?;
    Ok(())
}

fn main_header_block(
    main_iv: Option<[u8; 16]>,
    main_extra: &[u8],
    main_flags: u64,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<Bytes> {
    match header_keys {
        Some(keys) => encrypted_main_header_block(
            &keys.keys, main_iv, main_flags, None, main_extra, resources,
        ),
        None => {
            let mut main = Bytes::new(resources);
            write_main_header(&mut main, main_flags, None, main_extra, resources)?;
            Ok(main)
        }
    }
}

/// Twice a declared size covers members that cannot be stored when packing grows them.
fn widest_quick_open_offset(
    entries: &[ArchiveEntry],
    plan: &EnginePlan<'_>,
    main_header_len: u64,
) -> usize {
    // A block's fixed fields fit in a KiB.
    const BLOCK: u64 = 1024;
    let twice = |len: usize| (len as u64).saturating_mul(2);
    let comment = match &plan.archive_comment {
        Some(ArchiveCommentPlan::Plain(data) | ArchiveCommentPlan::Encrypted { data, .. }) => {
            twice(data.len()).saturating_add(BLOCK)
        }
        None => 0,
    };
    // The producer block, then the comment.
    let leading = main_header_len
        .saturating_add(BLOCK)
        .saturating_add(comment);
    let widest = entries.iter().fold(leading, |total, entry| {
        let declared = entry.source.len().unwrap_or(u64::MAX);
        let target = entry
            .redirection
            .as_ref()
            .map_or(0, |link| link.target_name.len());
        let member = declared
            .saturating_mul(2)
            .saturating_add(twice(entry.name.len()))
            .saturating_add(twice(target))
            .saturating_add(BLOCK);
        entry
            .services
            .iter()
            .fold(total.saturating_add(member), |total, service| {
                total
                    .saturating_add(twice(service.name.len()))
                    .saturating_add(twice(service.data.len()))
                    .saturating_add(BLOCK)
            })
    });
    (u64::BITS - widest.leading_zeros()).div_ceil(7).max(1) as usize
}

/// Spooled, as headers for many members would not fit in memory.
struct WrittenHeaders {
    headers: Spool,
    at: Records<(u64, usize)>,
    longest: usize,
}

impl WrittenHeaders {
    fn new(blocks: usize, resources: &WriterResources) -> Result<Self> {
        Ok(Self {
            headers: Spool::create_parked(resources)?,
            at: Records::new(blocks, resources)?,
            longest: 0,
        })
    }

    fn record(&mut self, at: u64, header: &[u8]) -> Result<()> {
        self.headers.write_all(header)?;
        self.headers.park();
        self.at.push((at, header.len()))?;
        self.longest = self.longest.max(header.len());
        Ok(())
    }

    fn into_payload(
        mut self,
        quick_open_at: u64,
        resources: &WriterResources,
    ) -> Result<(Spool, u32)> {
        let mut payload = Spool::create(resources)?;
        let mut checksum = crate::crc32::Crc32::new();
        let mut header = Bytes::zeroed(self.longest, resources)?;
        self.headers.rewind()?;
        for &(at, len) in self.at.iter() {
            self.headers.read_exact(&mut header[..len])?;
            append_quick_open_entry(
                &mut payload,
                &mut checksum,
                quick_open_at - at,
                &header[..len],
            )?;
        }
        payload.park();
        Ok((payload, checksum.finish()))
    }
}

/// A member hashed on its copy goes out behind a zeroed placeholder, patched everywhere it was copied.
#[allow(clippy::too_many_arguments)]
fn emit_block(
    block: PreparedBlock<'_>,
    entries: &[ArchiveEntry],
    sink: &mut CancellableOutput<'_, '_>,
    mirror: &mut Option<Spool>,
    quick_open: Option<&mut Spool>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    copy_work: &WorkTracker<'_>,
) -> Result<bool> {
    let PreparedBlock {
        header: prepared,
        payload,
        entry_index,
        patch,
        quick_open_record,
        ..
    } = block;
    let patch = match (patch, entry_index, sink.as_seekable()) {
        (Some(patch), Some(index), Some(output)) => Some((patch, index, output.stream_position()?)),
        (None, ..) => None,
        _ => {
            return Err(Error::InvalidArgument(
                "RAR 5 member header can only be patched in a seekable archive",
            ))
        }
    };
    let mirror_at = mirror.as_ref().map(Spool::len);
    let checksums = {
        let mut tee = Tee {
            output: sink.writer(),
            mirror: mirror.as_mut().map(|spool| spool as &mut dyn Write),
        };
        if patch.is_some() {
            tee.write_all(&Bytes::zeroed(prepared.len(), resources)?)?;
        } else {
            tee.write_all(&prepared)?;
        }
        let entry = patch
            .as_ref()
            .map(|(patch, index, _)| (*index, &entries[*index].name, patch.input_size));
        if let Some((index, name, size)) = entry {
            copy_work.entry_started(index, entries.len(), name, size);
        }
        let checksums = write_payload(
            payload,
            &mut tee,
            resources,
            progress,
            entry.is_some().then_some(copy_work),
        )?;
        if let Some((index, name, size)) = entry {
            copy_work.entry_finished(index, entries.len(), name, size);
        }
        checksums
    };
    let patched = match (patch, checksums) {
        (Some((patch, index, header_at)), Some(checksums)) => {
            let (crc32, hash) = checksums.finish();
            let patched = patch.render(
                &entries[index],
                crc32,
                hash,
                &prepared,
                header_keys,
                resources,
            )?;
            let changed = Error::InvalidArgument("RAR 5 header changed length when patched");
            let len = prepared.len() as u64;
            let output = sink
                .as_seekable()
                .expect("a patched header has a seekable archive");
            patch_header(output, header_at, len, &patched, changed.clone())?;
            if let (Some(spool), Some(at)) = (mirror.as_mut(), mirror_at) {
                patch_header(spool, at, len, &patched, changed)?;
            }
            Some(patched)
        }
        (None, None) => None,
        _ => {
            return Err(Error::InvalidArgument(
                "RAR 5 member was hashed on its copy without a header to patch",
            ))
        }
    };
    let Some(patched) = patched else {
        return Ok(false);
    };
    if let (Some(payload), Some((at, distance))) = (quick_open, quick_open_record) {
        // The record keeps its length, so it is rewritten where it stands.
        payload.seek_to(at)?;
        append_quick_open_entry(payload, &mut crate::crc32::Crc32::new(), distance, &patched)?;
        payload.park();
    }
    Ok(true)
}

/// Appends one quick-open record: how far back the header sits, then the
/// header itself.
///
/// The wrapper is `CRC32 || BlockSize || body`, and the checksum covers
/// `BlockSize` as well as the body. That is easy to get backwards, because the
/// length is written after the checksum it is part of. Checksumming the body
/// alone costs nothing visible: readers reject the wrapper, fall back to
/// walking the block chain, and report the archive as fine while the index
/// they were handed goes unused.
fn append_quick_open_entry(
    payload: &mut dyn Write,
    payload_crc: &mut crate::crc32::Crc32,
    distance: u64,
    header: &[u8],
) -> Result<()> {
    // At most three u64 vints. Keep framing on the stack and borrow the header
    // instead of cloning it into body and wrapper buffers.
    fn vint(out: &mut [u8], mut value: u64) -> usize {
        let mut len = 0;
        loop {
            out[len] = (value as u8 & 0x7f) | if value >= 0x80 { 0x80 } else { 0 };
            len += 1;
            value >>= 7;
            if value == 0 {
                return len;
            }
        }
    }
    let mut body_prefix = [0; 21];
    let mut len = 1; // Flags = 0.
    len += vint(&mut body_prefix[len..], distance);
    len += vint(&mut body_prefix[len..], header.len() as u64);
    let body_len = (header.len() as u64)
        .checked_add(len as u64)
        .ok_or(Error::InvalidArgument(
            "RAR 5 quick-open record size overflows",
        ))?;
    let mut size = [0; 10];
    let size_len = vint(&mut size, body_len);
    let parts = [&size[..size_len], &body_prefix[..len], header];
    let mut crc = crate::crc32::Crc32::new();
    for part in parts {
        crc.update(part);
    }
    // Combine the small framing fields into one write to the native spool.
    let mut framing = [0; 35];
    framing[..4].copy_from_slice(&crc.finish().to_le_bytes());
    framing[4..4 + size_len].copy_from_slice(&size[..size_len]);
    let framing_len = 4 + size_len + len;
    framing[4 + size_len..framing_len].copy_from_slice(&body_prefix[..len]);
    for part in [&framing[..framing_len], header] {
        payload.write_all(part)?;
        payload_crc.update(part);
    }
    Ok(())
}

/// A stored service block borrowing a named payload such as a comment.
fn stored_service_block<'a>(
    name: &[u8],
    data: &'a [u8],
    service_data: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    Ok(PreparedBlock {
        header: stored_service_header(
            name,
            data.len() as u64,
            crate::crc32::crc32(data),
            service_data,
            header_keys,
            resources,
        )?,
        payload: Payload::Borrowed(data),
        payload_len: data.len() as u64,
        quick_open_cached: false,
        entry_index: None,
        patch: None,
        quick_open_record: None,
    })
}

fn stored_service_header(
    name: &[u8],
    data_len: u64,
    crc32: u32,
    service_data: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedHeader> {
    let (specific, extra) = stored_service_parts(name, data_len, crc32, service_data, resources)?;
    prepared_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )
}

fn stored_service_parts(
    name: &[u8],
    data_len: u64,
    crc32: u32,
    service_data: &[u8],
    resources: &WriterResources,
) -> Result<(Bytes, Bytes)> {
    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data)?;
    let specific = stored_file_specific(name, data_len, crc32, 0, None, 0, resources)?;
    Ok((specific, extra))
}

// Archive-level identification is not a member or a quick-open entry. Its
// payload stays public even with encrypted headers, identifying the producing
// library without disclosing archive contents or borrowing the user's comment.
fn producer_block(
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'static>> {
    use crate::rar50::producer::{DATA, FLAGS, NAME};
    let data = DATA;
    let specific = stored_file_specific(
        NAME,
        data.len() as u64,
        crate::crc32::crc32(data),
        0,
        None,
        0,
        resources,
    )?;
    let header = prepared_header_image(
        HEAD_SERVICE,
        FLAGS,
        Some(data.len() as u64),
        &specific,
        &[],
        header_keys,
        resources,
    )?;
    Ok(PreparedBlock {
        header,
        payload: Payload::Borrowed(data),
        payload_len: data.len() as u64,
        quick_open_cached: false,
        entry_index: None,
        patch: None,
        quick_open_record: None,
    })
}

fn prepare_comment<'a>(
    comment: &ArchiveCommentPlan<'a>,
    write_keys: &mut WriteKeys<'a>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    match comment {
        ArchiveCommentPlan::Plain(data) => {
            let mut block = stored_service_block(b"CMT", data, &[], header_keys, resources)?;
            // Plain comments are listed by quick-open; encrypted ones are not.
            block.quick_open_cached = header_keys.is_none();
            Ok(block)
        }
        ArchiveCommentPlan::Encrypted { data, password } => encrypted_service_block(
            b"CMT",
            data,
            &[],
            password,
            write_keys,
            header_keys,
            resources,
        ),
    }
}

fn prepare_service<'a>(
    service: &'a super::ServiceEntry,
    write_keys: &mut WriteKeys<'a>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    match service.password.as_deref() {
        Some(password) => encrypted_service_block(
            &service.name,
            &service.data,
            &[],
            password,
            write_keys,
            header_keys,
            resources,
        ),
        None => stored_service_block(&service.name, &service.data, &[], header_keys, resources),
    }
}

/// A service block whose borrowed payload is encrypted during emission.
fn encrypted_service_block<'a>(
    name: &[u8],
    data: &'a [u8],
    service_data: &[u8],
    password: &'a [u8],
    write_keys: &mut WriteKeys<'a>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    super::validate_nonempty_password(password)?;
    let (salt, keys) = write_keys.for_password(password)?;
    let iv = fresh_iv()?;

    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data)?;
    write_file_encryption_record(&mut extra, salt, iv, keys.checked_password_record()?, true)?;
    // Like plain services, an encrypted one carries a CRC32 only, here as a MAC.
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        keys.checked_crc_mac(crate::crc32::crc32(data))?,
        0,
        None,
        0,
        resources,
    )?;
    let payload_len = (data.len() as u64)
        .checked_add(15)
        .ok_or(Error::InvalidArgument(
            "RAR 5 encrypted data size overflows",
        ))?
        & !15;
    let header = prepared_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(payload_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )?;
    Ok(PreparedBlock {
        header,
        payload: Payload::Encrypted {
            plain: Owned::new(PlainPayload::Borrowed(data), resources)?,
            keys,
            iv,
        },
        payload_len,
        quick_open_cached: false,
        entry_index: None,
        patch: None,
        quick_open_record: None,
    })
}

fn decoded_rar50_name_len(bytes: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return bytes.len();
    };
    if !text.contains('\u{fffe}') {
        return bytes.len();
    }
    text.chars()
        .map(|ch| match ch {
            '\u{fffe}' => 0,
            '\u{e080}'..='\u{e0ff}' => 1,
            _ => ch.len_utf8(),
        })
        .sum()
}

/// Builds a member's header and decides how its payload will be written.
#[allow(clippy::too_many_arguments)]
fn prepare_member<'a>(
    entry: &'a ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    hash_on_copy: bool,
    over: Option<&InPlace>,
    write_keys: &mut WriteKeys<'a>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'static>> {
    let hash_on_copy = hash_on_copy && member.store;
    let compression_info = compress::member_compression_info(&plan.compress, &member)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };
    let (crc32, hash, input_size) = (member.crc32, member.hash, member.input_size);
    let plain = if member.store {
        MemberPlainPayload::Stored(PreparedSource::new(&entry.source, &member, hash_on_copy))
    } else {
        MemberPlainPayload::Packed(member.packed)
    };

    let (payload, recipe) = match entry.password.as_deref() {
        Some(password) => {
            let (salt, keys) = write_keys.for_password(password)?;
            // Stored over its attempt, which overwrites every byte under
            // this IV, a member keeps the IV drawn for it, as a spooled one does.
            let iv = match over.and_then(|member| member.recipe.encryption.as_ref()) {
                Some(attempt) => attempt.iv,
                None => fresh_iv()?,
            };
            let recipe = MemberHeader {
                compression_info,
                input_size,
                // Encryption pads the payload up to the cipher block size.
                payload_len: padded_to_cipher_block(plain_len)?,
                encryption: Some(MemberEncryption {
                    salt,
                    iv,
                    keys: keys.clone(),
                }),
            };
            (
                Payload::Encrypted {
                    plain: Owned::new(plain.into(), resources)?,
                    keys,
                    iv,
                },
                recipe,
            )
        }
        None => (
            plain.into(),
            MemberHeader {
                compression_info,
                input_size,
                payload_len: plain_len,
                encryption: None,
            },
        ),
    };
    let (specific, extra) = recipe.parts(entry, crc32, hash, resources)?;
    let header = prepared_header_image_at_least(
        over.map_or(0, InPlace::header_len),
        over.and_then(|member| member.iv),
        HEAD_FILE,
        member_header_flags(&extra),
        Some(recipe.payload_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )?;

    Ok(PreparedBlock {
        header,
        payload,
        payload_len: recipe.payload_len,
        quick_open_cached: true,
        entry_index: None,
        patch: hash_on_copy.then_some(recipe),
        quick_open_record: None,
    })
}

/// A plain member with a CRC32 and its time in the base header has no extra
/// records, and then no extra area either.
fn member_header_flags(extra: &[u8]) -> u64 {
    if extra.is_empty() {
        HFL_DATA
    } else {
        HFL_DATA | HFL_EXTRA
    }
}

/// Spooling a large member costs as much temp disk as it packs to.
struct InPlace {
    recipe: MemberHeader,
    cipher: Option<OutgoingCipher>,
    header_at: u64,
    header_len: usize,
    /// The provisional header's, so the patched one draws no entropy.
    iv: Option<[u8; 16]>,
    /// Fixed by the declared size, so the archive does not depend on threads.
    width: usize,
    written: u64,
}

impl InPlace {
    fn open<'a>(
        entry: &'a ArchiveEntry,
        input_size: u64,
        plan: &EnginePlan<'_>,
        sink: &mut CancellableOutput<'_, '_>,
        write_keys: &mut WriteKeys<'a>,
        header_keys: Option<&HeaderEncryptionKeys>,
        resources: &WriterResources,
    ) -> Result<Self> {
        let compress = &plan.compress;
        // Drawn where a spooled member draws them, so both outputs draw alike.
        let encryption = match entry.password.as_deref() {
            Some(password) => {
                let (salt, keys) = write_keys.for_password(password)?;
                Some(MemberEncryption {
                    salt,
                    iv: fresh_iv()?,
                    keys,
                })
            }
            None => None,
        };
        let cipher = encryption
            .as_ref()
            .map(|encryption| OutgoingCipher::new(&encryption.keys, encryption.iv, resources))
            .transpose()?;
        let recipe = MemberHeader {
            compression_info: super::filter_policy::compression_info(
                compress.algorithm_version,
                compress.method,
                compress.dictionary_size,
                false,
            )?,
            input_size,
            payload_len: 0,
            encryption,
        };
        // A payload as long as the member is stored instead, so the packed
        // size always fits the width of the declared one, padded if encrypted.
        let widest = match cipher {
            Some(_) => padded_to_cipher_block(input_size)?,
            None => input_size,
        };
        let width = (u64::BITS - widest.leading_zeros()).div_ceil(7).max(1) as usize;
        // A placeholder hash keeps the provisional header as long as its patch.
        let placeholder = compress.blake2sp.then_some([0; 32]);
        let header = Self::header(
            &recipe,
            entry,
            0,
            placeholder,
            0,
            width,
            header_keys,
            None,
            resources,
        )?;
        let output = sink
            .as_seekable()
            .expect("a member goes out in place only to a seekable archive");
        let header_at = output.stream_position()?;
        output.write_all(&header)?;
        Ok(Self {
            recipe,
            cipher,
            header_at,
            header_len: header.len(),
            iv: header_keys.map(|_| header[..16].try_into().expect("sixteen bytes")),
            width,
            written: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn header(
        recipe: &MemberHeader,
        entry: &ArchiveEntry,
        crc32: u32,
        hash: Option<[u8; 32]>,
        packed_len: u64,
        width: usize,
        header_keys: Option<&HeaderEncryptionKeys>,
        iv: Option<[u8; 16]>,
        resources: &WriterResources,
    ) -> Result<Bytes> {
        let (specific, extra) = recipe.parts(entry, crc32, hash, resources)?;
        reserved_header_image(
            HEAD_FILE,
            member_header_flags(&extra),
            packed_len,
            width,
            &specific,
            &extra,
            header_keys,
            iv,
            resources,
        )
    }

    fn header_len(&self) -> usize {
        self.header_len
    }

    /// Those reaching the member's size are not written: it will be stored over them.
    fn write(&mut self, bytes: &[u8], sink: &mut CancellableOutput<'_, '_>) -> Result<()> {
        let written = self.written + bytes.len() as u64;
        if written < self.recipe.input_size {
            match self.cipher.as_mut() {
                Some(cipher) => cipher.write(bytes, sink.writer())?,
                None => sink.writer().write_all(bytes)?,
            }
            self.written = written;
        } else {
            self.written = self.recipe.input_size;
        }
        Ok(())
    }

    fn close(
        mut self,
        entry: &ArchiveEntry,
        closed: &ClosedMember,
        sink: &mut CancellableOutput<'_, '_>,
        header_keys: Option<&HeaderEncryptionKeys>,
        resources: &WriterResources,
    ) -> Result<Option<Bytes>> {
        let output = sink
            .as_seekable()
            .expect("a member goes out in place only to a seekable archive");
        if closed.store {
            output.seek(std::io::SeekFrom::Start(self.header_at))?;
            return Ok(None);
        }
        if closed.packed_len != self.written {
            return Err(Error::InvalidArgument(
                "RAR 5 member packed in place is not the size written",
            ));
        }
        let payload_len = match self.cipher.take() {
            Some(cipher) => {
                cipher.finish(output)?;
                padded_to_cipher_block(closed.packed_len)?
            }
            None => closed.packed_len,
        };
        let header = Self::header(
            &self.recipe,
            entry,
            closed.crc32,
            closed.hash,
            payload_len,
            self.width,
            header_keys,
            self.iv,
            resources,
        )?;
        patch_header(
            output,
            self.header_at,
            self.header_len as u64,
            &header,
            Error::InvalidArgument("RAR 5 header changed length when patched"),
        )?;
        Ok(Some(header))
    }
}

fn padded_to_cipher_block(len: u64) -> Result<u64> {
    len.checked_next_multiple_of(16)
        .ok_or(Error::InvalidArgument(
            "RAR 5 encrypted data size overflows",
        ))
}

/// Encrypting as the bytes go out means a packed member is never spooled.
#[cfg(feature = "encryption")]
struct OutgoingCipher {
    cipher: crate::crypto::rar50::Rar50Cipher,
    buffer: Bytes,
    pending: usize,
}

#[cfg(feature = "encryption")]
impl OutgoingCipher {
    const CHUNK: usize = 64 * 1024;

    fn new(keys: &Rar50Keys, iv: [u8; 16], resources: &WriterResources) -> Result<Self> {
        Ok(Self {
            cipher: crate::crypto::rar50::Rar50Cipher::new(keys.key, iv),
            buffer: Bytes::zeroed(Self::CHUNK, resources)?,
            pending: 0,
        })
    }

    fn write(&mut self, mut bytes: &[u8], output: &mut dyn Write) -> Result<()> {
        while !bytes.is_empty() {
            let take = bytes.len().min(Self::CHUNK - self.pending);
            self.buffer[self.pending..self.pending + take].copy_from_slice(&bytes[..take]);
            self.pending += take;
            bytes = &bytes[take..];
            let whole = self.pending & !15;
            self.cipher
                .encrypt_in_place(&mut self.buffer[..whole])
                .map_err(super::map_rar50_crypto_error)?;
            output.write_all(&self.buffer[..whole])?;
            self.buffer.copy_within(whole..self.pending, 0);
            self.pending -= whole;
        }
        Ok(())
    }

    /// Zero padding, as a spooled member gets, so both outputs match.
    fn finish(mut self, output: &mut dyn Write) -> Result<()> {
        let padded = padded_to_cipher_block(self.pending as u64)? as usize;
        self.buffer[self.pending..padded].fill(0);
        self.cipher
            .encrypt_in_place(&mut self.buffer[..padded])
            .map_err(super::map_rar50_crypto_error)?;
        output.write_all(&self.buffer[..padded])?;
        Ok(())
    }
}

/// Without encryption no member has a password, so none is encrypted in place.
#[cfg(not(feature = "encryption"))]
enum OutgoingCipher {}

#[cfg(not(feature = "encryption"))]
impl OutgoingCipher {
    fn new(_: &Rar50Keys, _: [u8; 16], _: &WriterResources) -> Result<Self> {
        Err(Error::FeatureDisabled {
            feature: "encryption",
        })
    }

    fn write(&mut self, _: &[u8], _: &mut dyn Write) -> Result<()> {
        match *self {}
    }

    fn finish(self, _: &mut dyn Write) -> Result<()> {
        match self {}
    }
}

/// Everything in a member's header but its checksums.
struct MemberHeader {
    compression_info: u64,
    input_size: u64,
    payload_len: u64,
    encryption: Option<MemberEncryption>,
}

struct MemberEncryption {
    salt: [u8; 16],
    iv: [u8; 16],
    keys: Rar50Keys,
}

impl MemberHeader {
    /// The CRC32 always goes in; the BLAKE2sp hash record only when the
    /// archive keeps hashes.
    fn parts(
        &self,
        entry: &ArchiveEntry,
        crc32: u32,
        hash: Option<[u8; 32]>,
        resources: &WriterResources,
    ) -> Result<(Bytes, Bytes)> {
        let mut extra = Bytes::new(resources);
        let (data_crc32, hash) = match &self.encryption {
            Some(encryption) => {
                write_file_encryption_record(
                    &mut extra,
                    encryption.salt,
                    encryption.iv,
                    encryption.keys.checked_password_record()?,
                    true,
                )?;
                (
                    encryption.keys.checked_crc_mac(crc32)?,
                    hash.map(|hash| encryption.keys.checked_hash_mac(hash))
                        .transpose()?,
                )
            }
            None => (crc32, hash),
        };
        // A link has no file payload to hash; its target is protected by the header CRC.
        if let Some(hash) = hash.filter(|_| entry.redirection.is_none()) {
            write_hash_record_with_value(&mut extra, hash)?;
        }
        super::headers::write_mtime_record(&mut extra, entry.mtime, entry.mtime_nanoseconds)?;
        if let Some(times) = entry.file_times {
            write_extra_record(&mut extra, super::super::FHEXTRA_HTIME, &times.encode()?)?;
        }
        if let Some(link) = &entry.redirection {
            let mut record = Bytes::new(resources);
            record.vint(link.redirection_type)?;
            record.vint(link.flags)?;
            record.vint(link.target_name.len() as u64)?;
            record.extend_from_slice(&link.target_name)?;
            write_extra_record(&mut extra, super::super::FHEXTRA_REDIR, &record)?;
        }

        let specific = file_specific(
            &entry.name,
            // Match Unix link stat size, while the packed payload remains empty.
            entry.redirection.as_ref().map_or(self.input_size, |link| {
                entry
                    .redirection_size
                    .unwrap_or_else(|| decoded_rar50_name_len(&link.target_name) as u64)
            }),
            data_crc32,
            entry.attributes,
            entry.mtime.filter(|_| entry.mtime_nanoseconds.is_none()),
            self.compression_info,
            entry.host_os,
            entry.is_directory,
            resources,
        )?;
        Ok((specific, extra))
    }

    /// The header again with the copy's checksums, at the prepared length.
    fn render(
        &self,
        entry: &ArchiveEntry,
        crc32: u32,
        hash: Option<[u8; 32]>,
        prepared: &[u8],
        header_keys: Option<&HeaderEncryptionKeys>,
        resources: &WriterResources,
    ) -> Result<Bytes> {
        let (specific, extra) = self.parts(entry, crc32, hash, resources)?;
        repeated_header_image(
            prepared,
            HEAD_FILE,
            member_header_flags(&extra),
            Some(self.payload_len),
            &specific,
            &extra,
            header_keys,
            resources,
        )
    }
}

/// Returns the payload's checksums when it was hashed on its copy.
fn write_payload(
    payload: Payload<'_>,
    output: &mut dyn Write,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    copy_work: Option<&WorkTracker<'_>>,
) -> Result<Option<ChecksumSink>> {
    check_cancelled(progress)?;
    match payload {
        Payload::Borrowed(data) => {
            output.write_all(data)?;
            Ok(None)
        }
        Payload::Stored(source) => {
            let work = copy_work.filter(|_| source.hashed_on_copy);
            let pipelined = crate::output_pipeline::admit_with(source.len, |bytes| {
                resources.reserve_preparation(bytes).ok()
            });
            let checksums = match pipelined {
                Some(_charge) => copy_stored_pipelined(&source, output, work)?,
                None => copy_stored_inline(&source, output, resources, work)?,
            };
            source.source.release();
            Ok(checksums)
        }
        Payload::Packed(mut packed) => {
            packed.copy_to(output)?;
            Ok(None)
        }
        Payload::Encrypted { plain, keys, iv } => {
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let chunk_size = match &*plain {
                PlainPayload::Borrowed(data) => {
                    data.len().clamp(1, ENCRYPT_CHUNK).div_ceil(16) * 16
                }
                _ => ENCRYPT_CHUNK,
            };
            let _permit = resources.acquire_cancellable(chunk_size as u64, 0, &|| {
                progress.is_some_and(ProgressReporter::is_cancelled)
            })?;
            match plain.into_inner() {
                PlainPayload::Stored(source) => {
                    let mut reader = source.open(copy_work.filter(|_| source.hashed_on_copy))?;
                    encrypt_reader_to(
                        &mut reader,
                        source.len,
                        output,
                        &keys,
                        iv,
                        ENCRYPT_CHUNK,
                        progress,
                        resources,
                    )
                    .map_err(|error| {
                        // Only a member hashed on its copy has not been
                        // measured before; running short is the source's doing.
                        if source.hashed_on_copy
                            && matches!(&error, Error::Io(io)
                                if io.kind == std::io::ErrorKind::UnexpectedEof)
                        {
                            Error::SourceChanged("entry source size changed while writing")
                        } else {
                            error
                        }
                    })?;
                    let checksums = reader.finish(&source, source.len)?;
                    source.source.release();
                    Ok(checksums)
                }
                PlainPayload::Packed(mut packed) => {
                    let len = packed.len();
                    packed.rewind()?;
                    encrypt_reader_to(
                        &mut packed,
                        len,
                        output,
                        &keys,
                        iv,
                        ENCRYPT_CHUNK,
                        progress,
                        resources,
                    )?;
                    Ok(None)
                }
                PlainPayload::Borrowed(mut data) => {
                    let len = data.len() as u64;
                    encrypt_reader_to(
                        &mut data, len, output, &keys, iv, chunk_size, progress, resources,
                    )?;
                    Ok(None)
                }
            }
        }
    }
}

fn copy_stored_inline(
    source: &PreparedSource,
    output: &mut dyn Write,
    resources: &WriterResources,
    work: Option<&WorkTracker<'_>>,
) -> Result<Option<ChecksumSink>> {
    let mut reader = source.open(work)?;
    let mut buffer = Bytes::zeroed(super::stored_block_len(source.len), resources)?;
    let mut copied = 0u64;
    while copied < source.len {
        let want = (source.len - copied).min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..want])?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        copied += read as u64;
    }
    reader.finish(source, copied)
}

fn copy_stored_pipelined(
    source: &PreparedSource,
    output: &mut dyn Write,
    work: Option<&WorkTracker<'_>>,
) -> Result<Option<ChecksumSink>> {
    let mut integrity = source.checksum_sink();
    // The producer and the checksum thread already fill a cap of two, so BLAKE2sp gets no split helper.
    let hash_cap = (crate::parallel::threads() <= 2).then_some(1);
    crate::output_pipeline::run(
        |chunks| produce_stored(source, work, chunks),
        &mut |chunk: &[u8]| {
            let _cap = crate::parallel::ThreadCap::set(hash_cap);
            integrity.update(chunk);
        },
        output,
    )
    .map_err(|error| match error {
        crate::output_pipeline::PipeError::Produce(error) => error,
        crate::output_pipeline::PipeError::Write(error) => error.into(),
    })?;
    source.finish_checksums(integrity)
}

fn produce_stored(
    source: &PreparedSource,
    work: Option<&WorkTracker<'_>>,
    chunks: &mut crate::output_pipeline::Chunks<'_>,
) -> Result<()> {
    let mut reader = source.source.open()?;
    let mut copied = 0u64;
    while copied < source.len {
        let space = chunks.space()?;
        let want = (source.len - copied).min(space.len() as u64) as usize;
        let read = reader.read(&mut space[..want])?;
        if read == 0 {
            break;
        }
        chunks.commit(read)?;
        copied += read as u64;
        if work.is_some_and(|work| !work.advance(read as u64)) {
            return Err(Error::Cancelled);
        }
    }
    crate::write_stream::check_source_length(
        &mut *reader,
        copied,
        source.len,
        "entry source size changed while writing",
    )
}

/// Computes the recovery record over `prefix` and writes its service block.
/// Length of the recovery block [`write_recovery_service`] writes over
/// `prefix_len` bytes, header included.
fn recovery_block_len(
    prefix_len: u64,
    recovery_percent: u64,
    header_encrypted: bool,
    resources: &WriterResources,
) -> Result<u64> {
    #[cfg(not(feature = "recovery"))]
    {
        let _ = (prefix_len, recovery_percent, header_encrypted, resources);
        Err(Error::FeatureDisabled {
            feature: "recovery",
        })
    }
    #[cfg(feature = "recovery")]
    {
        let payload_len = plan_inline_recovery(prefix_len, recovery_percent)?.payload_size()?;
        let mut service_data = Bytes::new(resources);
        service_data.vint(recovery_percent)?;
        super::layout::stored_service_block_len(
            b"RR",
            payload_len,
            &service_data,
            header_encrypted,
            resources,
        )
    }
}

fn write_recovery_service(
    recovery_percent: u64,
    prefix: &mut Spool,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    output: &mut dyn Write,
) -> Result<u64> {
    #[cfg(not(feature = "recovery"))]
    {
        let _ = (
            recovery_percent,
            prefix,
            header_keys,
            resources,
            progress,
            output,
        );
        Err(Error::FeatureDisabled {
            feature: "recovery",
        })
    }
    #[cfg(feature = "recovery")]
    {
        if let Some(allowance) = &resources.execution {
            return recovery_service_with_allowance(
                recovery_percent,
                prefix,
                header_keys,
                resources,
                progress,
                output,
                allowance,
            );
        }
        recovery_service_with_allowance(
            recovery_percent,
            prefix,
            header_keys,
            resources,
            progress,
            output,
            &crate::codec::workspace::Allowance::default(),
        )
    }
}

#[cfg(feature = "recovery")]
fn recovery_service_with_allowance<B: crate::codec::workspace::Budget>(
    recovery_percent: u64,
    prefix: &mut Spool,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    output: &mut dyn Write,
    allowance: &B,
) -> Result<u64> {
    let prefix_len = prefix.len();
    let plan = plan_inline_recovery(prefix_len, recovery_percent)?;
    let (mode, required) = choose_recovery_memory_mode(plan, resources.memory_limit())?;
    let (mode, required) = if let Some(allowance) = &resources.execution {
        crate::recovery::rar5::choose_recovery_capacity_mode(
            plan,
            resources.memory_limit(),
            allowance,
        )?
    } else {
        (mode, required)
    };
    let _permit = resources.acquire_cancellable(required, 0, &|| {
        progress.is_some_and(ProgressReporter::is_cancelled)
    })?;

    let mut scratch = match mode {
        crate::recovery::rar5::RecoveryMemoryMode::Striped { .. } => {
            Some(Spool::create(resources)?)
        }
        crate::recovery::rar5::RecoveryMemoryMode::Resident => None,
    };
    let mut payload = Spool::create(resources)?;
    prefix.rewind()?;
    let built = streamed_recovery_with_allowance(
        &mut CancellableIo {
            inner: prefix,
            progress,
        },
        prefix_len,
        plan,
        mode,
        scratch
            .as_mut()
            .map(|scratch| scratch as &mut dyn ReadWriteSeek),
        &mut CancellableIo {
            inner: &mut payload,
            progress,
        },
        progress,
        1,
        allowance,
    )
    .map_err(|error| {
        if check_cancelled(progress).is_err() {
            Error::Cancelled
        } else {
            error.into()
        }
    })?;

    debug_assert_eq!(built.plan.payload_size(), Ok(built.payload_len));

    let mut service_data = Bytes::new(resources);
    service_data.vint(recovery_percent)?;
    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data)?;
    let specific = stored_file_specific(
        b"RR",
        built.payload_len,
        built.payload_crc32,
        0,
        None,
        0,
        resources,
    )?;
    let header = match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(built.payload_len),
            &specific,
            &extra,
            &[],
            resources,
        )?,
        None => block_header_image(
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(built.payload_len),
            &specific,
            &extra,
            resources,
        )?,
    };
    output.write_all(&header)?;
    payload.copy_to(output)?;
    Ok(header.len() as u64 + built.payload_len)
}

/// Writes to the archive and, when a recovery record is coming, keeps a copy
/// for the parity pass to read.
struct Tee<'a> {
    output: &'a mut dyn Write,
    mirror: Option<&'a mut dyn Write>,
}

impl Write for Tee<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.write_all(buffer)?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.write_all(buffer)?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

/// Where a member's payload bytes come from when a volume set slices them up.
enum FragmentSource {
    Packed(Spool),
    Stored {
        prepared: PreparedSource,
        emitted: Owned<ChecksumSink>,
    },
}

impl FragmentSource {
    /// Copies a fragment's bytes to `output`, returning their checksums when
    /// asked, so the fragment's header can be patched without a second read.
    fn emit_range(
        &mut self,
        start: u64,
        len: u64,
        output: &mut dyn Write,
        want_checksums: bool,
        blake2sp: bool,
        resources: &WriterResources,
    ) -> Result<Option<FragmentChecksums>> {
        let mut fragment = want_checksums.then(|| ChecksumSink::new(blake2sp));
        match self {
            Self::Packed(spool) => {
                spool.copy_range_to(
                    start,
                    len,
                    &mut Tee {
                        output,
                        mirror: fragment.as_mut().map(|sink| sink as &mut dyn Write),
                    },
                )?;
            }
            Self::Stored { prepared, emitted } => {
                let mut buffer = Bytes::zeroed(64 * 1024, resources)?;
                let mut reader = prepared.source.open()?;
                reader.seek(std::io::SeekFrom::Start(start))?;
                let mut remaining = len;
                while remaining != 0 {
                    let want = remaining.min(buffer.len() as u64) as usize;
                    reader
                        .read_exact(&mut buffer[..want])
                        .map_err(|error| match error.kind() {
                            std::io::ErrorKind::UnexpectedEof => {
                                Error::SourceChanged("entry source size changed while writing")
                            }
                            _ => error.into(),
                        })?;
                    output.write_all(&buffer[..want])?;
                    emitted.write_all(&buffer[..want])?;
                    if let Some(fragment) = fragment.as_mut() {
                        fragment.write_all(&buffer[..want])?;
                    }
                    remaining -= want as u64;
                }
                if start + len == prepared.len {
                    crate::write_stream::check_source_length(
                        &mut *reader,
                        start + len,
                        prepared.len,
                        "entry source size changed while writing",
                    )?;
                    let blake2sp = prepared.hash.is_some();
                    prepared.verify(std::mem::replace(
                        &mut **emitted,
                        ChecksumSink::new(blake2sp),
                    ))?;
                }
            }
        }
        Ok(fragment.map(|sink| {
            let (crc32, hash) = sink.finish();
            FragmentChecksums { crc32, hash }
        }))
    }
}

/// What a fragment that is not the last one reports about its own bytes.
#[derive(Clone, Copy)]
struct FragmentChecksums {
    crc32: u32,
    hash: Option<[u8; 32]>,
}

/// Discards what it is given and keeps the running checksums: a CRC32, and a
/// BLAKE2sp hash only for an archive that stores one.
struct ChecksumSink {
    crc: crate::crc32::Crc32,
    hash: Option<crate::rar50::blake2sp::Hasher>,
}

impl ChecksumSink {
    fn new(blake2sp: bool) -> Self {
        Self {
            crc: crate::crc32::Crc32::new(),
            hash: blake2sp.then(crate::rar50::blake2sp::Hasher::new),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        if let Some(hash) = &mut self.hash {
            hash.update(bytes);
        }
    }

    fn finish(self) -> (u32, Option<[u8; 32]>) {
        (
            self.crc.finish(),
            self.hash.map(crate::rar50::blake2sp::Hasher::finalize),
        )
    }
}

impl Write for ChecksumSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A member ready to be sliced across volumes.
struct VolumeMember<'a> {
    name: &'a [u8],
    is_directory: bool,
    mtime: Option<u32>,
    mtime_nanoseconds: Option<u32>,
    file_times: Option<crate::file_times::TimeRecord>,
    attributes: u64,
    host_os: u64,
    unpacked_size: u64,
    crc32: u32,
    hash: Option<[u8; 32]>,
    compression_info: u64,
    payload_len: u64,
    source: FragmentSource,
    /// Encryption record for the file header, when the payload is encrypted.
    encryption: Option<([u8; 16], [u8; 16], [u8; 12])>,
}

struct MemberProgress<'a, 'p> {
    entries: &'a [ArchiveEntry],
    work: &'a crate::write_progress::WorkTracker<'p>,
}
impl compress::CompressionProgress for MemberProgress<'_, '_> {
    fn is_cancelled(&self) -> bool {
        self.work.is_cancelled()
    }
    fn advance(&self, bytes: u64) -> bool {
        self.work.advance(bytes)
    }
    fn started(&self, index: usize, size: u64) {
        self.work
            .entry_started(index, self.entries.len(), &self.entries[index].name, size);
    }
    fn finished(&self, index: usize, size: u64) {
        self.work
            .entry_finished(index, self.entries.len(), &self.entries[index].name, size);
    }
}

/// Writes a multi-volume archive, handing each volume to `sink` as it is
/// finished rather than keeping the set in memory. No volume is longer than
/// `volume_size` bytes, headers and recovery record included.
pub(super) fn write_volumes<'a>(
    entries: &'a [ArchiveEntry],
    plan: EnginePlan<'a>,
    volume_size: u64,
    sink: &mut dyn super::VolumeSink,
    resources: &WriterResources,
) -> Result<()> {
    if volume_size == 0 {
        return Err(Error::InvalidArgument("RAR 5 volume size is zero"));
    }
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let mut write_keys = WriteKeys::default();
    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            plan.header_password
                .into_iter()
                .chain(entries.iter().filter_map(|entry| entry.password.as_deref())),
        )?;
        Some(header_encryption_keys(&mut write_keys, password)?)
    } else {
        None
    };

    let mut sources = Records::new(entries.len(), resources)?;
    for entry in entries {
        sources.push(entry.source.clone())?;
    }
    let total_input = total_input_size(entries)?;
    let total_entries = entries.len();
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationStarted {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
    let work = crate::write_progress::WorkTracker::new(
        plan.progress,
        crate::WriteOperation::Compression,
        total_input,
    );
    let compressed = compress::compress_members_with_context(
        &sources,
        &plan.compress,
        resources,
        &MemberProgress {
            entries,
            work: &work,
        },
        &|index, error| member_error(error, &entries[index].name, "compressing"),
    )?;

    let mut members = Records::new(entries.len(), resources)?;
    for (entry, member) in entries.iter().zip(compressed) {
        check_cancelled(plan.progress)?;
        members.push(
            prepare_volume_member(entry, member, &plan, &mut write_keys, resources)
                .map_err(|error| member_error(error, &entry.name, "preparing volume payload"))?,
        )?;
    }
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationFinished {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }

    report_emission(plan.progress, true);
    let mut writer = VolumeWriter {
        volume_size,
        solid: plan.compress.solid,
        recovery_percent: plan.recovery_percent,
        header_keys: header_keys.as_ref(),
        progress: plan.progress,
        resources,
        sink,
        body: None,
        head_crypt_len: 0,
        fixed_len: 0,
        body_budget: None,
        fragments_in_volume: 0,
        volume_index: 0,
        trailing_producer: None,
        trailing_len: 0,
    };

    for mut member in members {
        writer
            .write_member(&mut member)
            .map_err(|error| member_error(error, member.name, "writing volume member"))?;
    }
    writer.finish()?;
    check_cancelled(plan.progress)?;
    report_emission(plan.progress, false);
    Ok(())
}

/// Compresses and, if needed, encrypts one member into a form that can be cut
/// at any byte boundary.
fn prepare_volume_member<'a>(
    entry: &'a ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    write_keys: &mut WriteKeys<'a>,
    resources: &WriterResources,
) -> Result<VolumeMember<'a>> {
    let progress = plan.progress;
    check_cancelled(progress)?;
    let compression_info = compress::member_compression_info(&plan.compress, &member)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };

    match entry.password.as_deref() {
        Some(password) => {
            let (salt, keys) = write_keys.for_password(password)?;
            let iv = fresh_iv()?;

            // A volume boundary can fall anywhere, and the cipher runs as one
            // chain over the member, so encrypt it up front into scratch
            // storage and slice the ciphertext.
            let mut encrypted = Spool::create(resources)?;
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let _permit = resources.acquire_cancellable(ENCRYPT_CHUNK as u64, 0, &|| {
                progress.is_some_and(ProgressReporter::is_cancelled)
            })?;
            if member.store {
                let source = PreparedSource::new(&entry.source, &member, false);
                let mut reader = source.open(None)?;
                encrypt_reader_to(
                    &mut reader,
                    plain_len,
                    &mut encrypted,
                    &keys,
                    iv,
                    ENCRYPT_CHUNK,
                    progress,
                    resources,
                )?;
                reader.finish(&source, source.len)?;
            } else {
                let mut packed = member.packed;
                packed.rewind()?;
                encrypt_reader_to(
                    &mut packed,
                    plain_len,
                    &mut encrypted,
                    &keys,
                    iv,
                    ENCRYPT_CHUNK,
                    progress,
                    resources,
                )?;
            }
            let payload_len = encrypted.len();
            encrypted.park();
            Ok(VolumeMember {
                name: &entry.name,
                is_directory: entry.is_directory,
                mtime: entry.mtime,
                mtime_nanoseconds: entry.mtime_nanoseconds,
                file_times: entry.file_times,
                attributes: entry.attributes,
                host_os: entry.host_os,
                unpacked_size: member.input_size,
                crc32: keys.checked_crc_mac(member.crc32)?,
                hash: member
                    .hash
                    .map(|hash| keys.checked_hash_mac(hash))
                    .transpose()?,
                compression_info,
                payload_len,
                source: FragmentSource::Packed(encrypted),
                encryption: Some((salt, iv, keys.checked_password_record()?)),
            })
        }
        None => Ok(VolumeMember {
            name: &entry.name,
            is_directory: entry.is_directory,
            mtime: entry.mtime,
            mtime_nanoseconds: entry.mtime_nanoseconds,
            file_times: entry.file_times,
            attributes: entry.attributes,
            host_os: entry.host_os,
            unpacked_size: member.input_size,
            crc32: member.crc32,
            hash: member.hash,
            compression_info,
            payload_len: plain_len,
            source: if member.store {
                FragmentSource::Stored {
                    emitted: Owned::new(ChecksumSink::new(member.hash.is_some()), resources)?,
                    prepared: PreparedSource::new(&entry.source, &member, false),
                }
            } else {
                FragmentSource::Packed(member.packed)
            },
            encryption: None,
        }),
    }
}

struct VolumeWriter<'a> {
    volume_size: u64,
    solid: bool,
    recovery_percent: Option<u64>,
    header_keys: Option<&'a HeaderEncryptionKeys>,
    progress: Option<ProgressReporter<'a>>,
    resources: &'a WriterResources,
    sink: &'a mut dyn super::VolumeSink,
    /// Body of the volume being filled, held on disk rather than in memory.
    body: Option<Spool>,
    /// The encryption header, if any: the same length in every volume.
    head_crypt_len: u64,
    /// Signature, encryption header and end block together.
    fixed_len: u64,
    /// How long the body may grow before the finished volume would pass
    /// `volume_size`, worked out the first time a fragment has to be cut.
    body_budget: Option<u64>,
    fragments_in_volume: u64,
    volume_index: u64,
    /// A later volume's producer record, written after its files when it closes.
    trailing_producer: Option<PreparedBlock<'static>>,
    /// Its length, which the volume's budget sets aside.
    trailing_len: u64,
}

impl VolumeWriter<'_> {
    /// Cuts one member across as many volumes as it takes.
    fn write_member(&mut self, member: &mut VolumeMember) -> Result<()> {
        check_cancelled(self.progress)?;
        let mut start = 0u64;
        let mut split_before = false;
        // Zero-length members still need a header of their own.
        loop {
            if self.body.is_none() {
                self.start_volume()?;
            }
            let remaining = member.payload_len - start;
            // A volume is closed only once the next fragment cannot fit in it,
            // because until then we cannot say whether it is the last one, and
            // its end-of-archive block has to say which.
            let Some(fragment_len) = self.fragment_room(member, split_before, remaining)? else {
                if self.fragments_in_volume == 0 {
                    return Err(Error::InvalidArgument(
                        "RAR 5 volume size is too small to hold a member header",
                    ));
                }
                self.finish_volume(true)?;
                continue;
            };
            let split_after = start + fragment_len < member.payload_len;
            // A fragment that is not the last one has no whole-member checksum
            // to report, so the field carries the CRC32 of the bytes this
            // volume stores. That is what WinRAR puts there, and it lets a
            // single volume be checked on its own. Those are only known once
            // the bytes are copied, so the header goes out as a placeholder of
            // the same length and is patched afterwards.
            let header_len = self.fragment_header_len(member, fragment_len, split_before)?;
            let body = self.body.as_mut().expect("volume started");
            let header_at = body.len();
            body.write_all(&vec![0; header_len as usize])?;
            let blake2sp = member.hash.is_some();
            let fragment_checksums = member.source.emit_range(
                start,
                fragment_len,
                &mut CancellableIo {
                    inner: &mut *body,
                    progress: self.progress,
                },
                split_after,
                blake2sp,
                self.resources,
            )?;
            let header = fragment_header(
                member,
                fragment_len,
                split_before,
                fragment_checksums,
                self.header_keys,
                self.resources,
            )?;
            patch_header(
                body,
                header_at,
                header_len,
                &header,
                Error::WriterFailure("RAR 5 fragment header changed length when patched"),
            )?;

            self.fragments_in_volume += 1;
            start += fragment_len;
            split_before = true;

            if start >= member.payload_len {
                return Ok(());
            }
        }
    }

    /// The longest next fragment of `member` that still fits in this volume
    /// with its header, or `None` when not even the header and one byte do.
    /// A member with nothing left still needs room for its header.
    fn fragment_room(
        &mut self,
        member: &VolumeMember,
        split_before: bool,
        remaining: u64,
    ) -> Result<Option<u64>> {
        // A later volume's producer record joins the body when it closes.
        let used = self.body.as_ref().expect("volume started").len() + self.trailing_len;
        // Most of the time the rest of the member fits as it is, and one
        // layout check says so without working out the whole budget.
        let header = self.fragment_header_len(member, remaining, split_before)?;
        if self.fits(used.saturating_add(header).saturating_add(remaining))? {
            return Ok(Some(remaining));
        }
        let room = self.body_budget()?.saturating_sub(used);
        let mut len = remaining.min(room);
        let header = self.fragment_header_len(member, len, split_before)?;
        if header.saturating_add(len) > room {
            // A shorter fragment never has a longer header, so this fits.
            len = room.saturating_sub(header);
        }
        if len == 0 && remaining > 0 {
            return Ok(None);
        }
        let header = self.fragment_header_len(member, len, split_before)?;
        Ok((header.saturating_add(len) <= room).then_some(len))
    }

    /// A fragment header's size depends only on the fragment's length: the
    /// checksums it carries are fixed width, so any values measure the same.
    fn fragment_header_len(
        &self,
        member: &VolumeMember,
        fragment_len: u64,
        split_before: bool,
    ) -> Result<u64> {
        let header = fragment_header(
            member,
            fragment_len,
            split_before,
            None,
            self.header_keys,
            self.resources,
        )?;
        Ok(header.len() as u64)
    }

    /// Everything this volume adds around a body of `body_len` bytes: the
    /// fixed blocks, the main header and the recovery record.
    fn volume_overhead(&self, body_len: u64) -> Result<u64> {
        let layout = settle_layout(
            &self.layout_inputs(self.volume_index, self.head_crypt_len, body_len),
            self.resources,
        )?;
        let mut len = self
            .fixed_len
            .checked_add(layout.main_header_len)
            .ok_or(Error::InvalidArgument("RAR 5 volume layout overflows"))?;
        if let (Some(percent), Some(prefix)) = (self.recovery_percent, layout.recovery_prefix_len) {
            // A volume its recovery record cannot cover fits no volume size,
            // so a volume closes before it grows that large.
            if !recovery_covers(prefix, percent) {
                return Ok(u64::MAX);
            }
            len = len
                .checked_add(recovery_block_len(
                    prefix,
                    percent,
                    self.header_keys.is_some(),
                    self.resources,
                )?)
                .ok_or(Error::InvalidArgument("RAR 5 volume layout overflows"))?;
        }
        Ok(len)
    }

    fn fits(&self, body_len: u64) -> Result<bool> {
        Ok(self.volume_overhead(body_len)?.saturating_add(body_len) <= self.volume_size)
    }

    /// The most body bytes this volume can hold and still come in at or under
    /// `volume_size` once its main header, recovery record and end block are
    /// added.
    ///
    /// That overhead only grows with the body, through the main header's
    /// variable-length offsets and the recovery record's size. So taking the
    /// overhead of the largest body there could be off the volume size gives a
    /// body that fits, and it is exact when the overhead did not shrink on the
    /// way down, which without a recovery record it never does. Whatever a
    /// smaller recovery record gives back is found by a binary search over
    /// that gap.
    fn body_budget(&mut self) -> Result<u64> {
        if let Some(budget) = self.body_budget {
            return Ok(budget);
        }
        let largest = self.volume_size.saturating_sub(self.fixed_len);
        let mut fitting = self
            .volume_size
            .saturating_sub(self.volume_overhead(largest)?);
        let budget = if self.fits(fitting)? {
            // The overhead never shrinks as the body grows, so nothing longer
            // than the volume less the overhead of an empty body can fit.
            let mut too_long = self.volume_size.saturating_sub(self.volume_overhead(0)?) + 1;
            while too_long - fitting > 1 {
                let middle = fitting + (too_long - fitting) / 2;
                if self.fits(middle)? {
                    fitting = middle;
                } else {
                    too_long = middle;
                }
            }
            fitting
        } else {
            0
        };
        self.body_budget = Some(budget);
        Ok(budget)
    }

    /// The first volume carries no volume number: RAR leaves it out there, and
    /// python-rarfile only treats a volume without one as the first.
    fn main_flags(&self, volume_number: u64) -> u64 {
        let mut main_flags = crate::rar50::MHFL_VOLUME;
        if volume_number > 0 {
            main_flags |= crate::rar50::MHFL_VOLUME_NUMBER;
        }
        if self.solid {
            main_flags |= MHFL_SOLID;
        }
        if self.recovery_percent.is_some() {
            main_flags |= MHFL_RECOVERY;
        }
        main_flags
    }

    fn layout_inputs(
        &self,
        volume_number: u64,
        head_crypt_len: u64,
        body_len: u64,
    ) -> LayoutInputs<'static> {
        LayoutInputs {
            header_encrypted: self.header_keys.is_some(),
            head_crypt_len,
            main_flags: self.main_flags(volume_number),
            volume_number: (volume_number > 0).then_some(volume_number),
            archive_metadata: None,
            metadata_record: None,
            body_len,
            quick_open_payload_len: None,
            quick_open_width: 0,
            recovery_percent: self.recovery_percent,
        }
    }

    fn head_crypt(&self) -> Result<Bytes> {
        let mut block = Bytes::new(self.resources);
        if let Some(keys) = self.header_keys {
            write_head_crypt(&mut block, keys, self.resources)?;
        }
        Ok(block)
    }

    fn end_block(&self, more_volumes_follow: bool) -> Result<Bytes> {
        let end_flags = if more_volumes_follow {
            crate::rar50::EFL_NEXT_VOLUME
        } else {
            0
        };
        match self.header_keys {
            Some(keys) => encrypted_header_block(
                &keys.keys,
                HEAD_END,
                0,
                None,
                &super::end_header_specific(end_flags),
                &[],
                &[],
                self.resources,
            ),
            None => {
                let mut end = Bytes::new(self.resources);
                write_end_header(&mut end, end_flags, self.resources)?;
                Ok(end)
            }
        }
    }

    fn finish(mut self) -> Result<()> {
        // The public volume entry point rejects empty member lists; each
        // nonempty member starts a volume, even when its payload is empty.
        self.finish_volume(false)
    }

    fn start_volume(&mut self) -> Result<()> {
        let mut body = Spool::create(self.resources)?;
        let marker = producer_block(self.header_keys, self.resources)?;
        self.trailing_len = 0;
        if self.volume_index == 0 {
            body.write_all(&marker.header)?;
            write_payload(
                marker.payload,
                &mut body,
                self.resources,
                self.progress,
                None,
            )?;
        } else {
            // A split member's header comes first in a later volume, as RAR
            // writes it; python-rarfile reads stored members on that basis.
            self.trailing_len = marker.header.len() as u64 + marker.payload_len;
            self.trailing_producer = Some(marker);
        }
        self.body = Some(body);
        self.head_crypt_len = self.head_crypt()?.len() as u64;
        self.fixed_len =
            RAR50_SIGNATURE.len() as u64 + self.head_crypt_len + self.end_block(true)?.len() as u64;
        self.body_budget = None;
        self.fragments_in_volume = 0;
        Ok(())
    }

    fn finish_volume(&mut self, more_volumes_follow: bool) -> Result<()> {
        let mut body = self.body.take().expect("volume started");
        if let Some(marker) = self.trailing_producer.take() {
            body.write_all(&marker.header)?;
            write_payload(
                marker.payload,
                &mut body,
                self.resources,
                self.progress,
                None,
            )?;
        }
        let volume_number = self.volume_index;
        self.volume_index += 1;

        let head_crypt = self.head_crypt()?;
        let main_flags = self.main_flags(volume_number);
        let stored_number = (volume_number > 0).then_some(volume_number);
        let layout = resolve_layout(
            &self.layout_inputs(volume_number, head_crypt.len() as u64, body.len()),
            self.resources,
        )?;

        check_cancelled(self.progress)?;
        let raw_output = self.sink.start_volume(volume_number)?;
        let mut output = CancellableIo {
            inner: raw_output,
            progress: self.progress,
        };
        let mut mirror = match self.recovery_percent {
            Some(_) => Some(Spool::create(self.resources)?),
            None => None,
        };
        let mut written;
        {
            let mut tee = Tee {
                output: &mut output,
                mirror: mirror.as_mut().map(|spool| spool as &mut dyn Write),
            };
            let main = match self.header_keys {
                Some(keys) => encrypted_main_header_block(
                    &keys.keys,
                    None,
                    main_flags,
                    stored_number,
                    &layout.main_extra,
                    self.resources,
                )?,
                None => {
                    let mut main = Bytes::new(self.resources);
                    write_main_header(
                        &mut main,
                        main_flags,
                        stored_number,
                        &layout.main_extra,
                        self.resources,
                    )?;
                    main
                }
            };
            debug_assert_eq!(main.len() as u64, layout.main_header_len);

            tee.write_all(RAR50_SIGNATURE)?;
            tee.write_all(&head_crypt)?;
            tee.write_all(&main)?;
            body.rewind()?;
            std::io::copy(&mut body, &mut tee)?;
            written = RAR50_SIGNATURE.len() as u64
                + head_crypt.len() as u64
                + main.len() as u64
                + body.len();
        }

        if let Some(recovery_percent) = self.recovery_percent {
            let mirror = mirror.as_mut().expect("recovery mirrors the volume");
            debug_assert_eq!(layout.recovery_prefix_len, Some(mirror.len()));
            written += write_recovery_service(
                recovery_percent,
                mirror,
                self.header_keys,
                self.resources,
                self.progress,
                &mut output,
            )?;
        }

        let end = self.end_block(more_volumes_follow)?;
        output.write_all(&end)?;
        written += end.len() as u64;
        output.flush()?;
        drop(output);

        if written > self.volume_size {
            return Err(Error::WriterFailure(
                "RAR 5 volume came out longer than the volume size",
            ));
        }
        self.sink.finish_volume(volume_number, written)
    }
}

/// Builds the file header for one fragment of a member.
///
/// Every fragment repeats the member's metadata. The last one carries the
/// member's own checksum and hash; the rest carry `fragment` over the bytes
/// they store, which is what WinRAR puts there and lets one volume be checked
/// on its own. Encrypted fragments checksum the ciphertext, so that check needs
/// no password, and like WinRAR they leave the hash-MAC flag off; with it set,
/// unrar MACs the checksum it computes and reports a packed data checksum error.
///
/// Every fragment carries a CRC32, and a hash record too when the archive keeps
/// hashes. A reader takes the hash record as the member's checksum type when it
/// has one, and unrar picks that type from the first fragment and compares it
/// against the last, so a fragment that offered only a CRC32 while the last
/// offered a hash would fail a member that is perfectly intact.
fn fragment_header(
    member: &VolumeMember,
    fragment_len: u64,
    split_before: bool,
    fragment: Option<FragmentChecksums>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<Bytes> {
    let split_after = fragment.is_some();
    let mut extra = Bytes::new(resources);
    if let Some((salt, iv, check_value)) = member.encryption {
        write_file_encryption_record(&mut extra, salt, iv, check_value, !split_after)?;
    }
    if let Some(hash) = fragment.map_or(member.hash, |f| f.hash) {
        write_hash_record_with_value(&mut extra, hash)?;
    }
    super::headers::write_mtime_record(&mut extra, member.mtime, member.mtime_nanoseconds)?;
    if let Some(times) = member.file_times {
        write_extra_record(&mut extra, super::super::FHEXTRA_HTIME, &times.encode()?)?;
    }
    let specific = file_specific(
        member.name,
        member.unpacked_size,
        fragment.map_or(member.crc32, |f| f.crc32),
        member.attributes,
        member.mtime.filter(|_| member.mtime_nanoseconds.is_none()),
        member.compression_info,
        member.host_os,
        member.is_directory,
        resources,
    )?;

    let mut flags = member_header_flags(&extra);
    if split_before {
        flags |= crate::rar50::HFL_SPLIT_BEFORE;
    }
    if split_after {
        flags |= crate::rar50::HFL_SPLIT_AFTER;
    }
    match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_FILE,
            flags,
            Some(fragment_len),
            &specific,
            &extra,
            &[],
            resources,
        ),
        None => block_header_image(
            HEAD_FILE,
            flags,
            Some(fragment_len),
            &specific,
            &extra,
            resources,
        ),
    }
}

fn report_emission(progress: Option<ProgressReporter<'_>>, started: bool) {
    use crate::{WriteOperation, WriteProgressEvent};
    if let Some(progress) = progress {
        progress.report(if started {
            WriteProgressEvent::OperationStarted {
                operation: WriteOperation::Emission,
                total_bytes: None,
                total_entries: None,
                pass: 1,
            }
        } else {
            WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Emission,
                total_bytes: None,
                total_entries: None,
                pass: 1,
            }
        });
    }
}

fn member_error(error: Error, name: &[u8], operation: &'static str) -> Error {
    // Cancellation remains an operation-level result. A streaming fallback can
    // already have supplied the same member context; do not duplicate it.
    if error.kind() == crate::ErrorKind::Cancelled
        || error
            .entry_context()
            .is_some_and(|(existing, _)| existing == name)
    {
        error
    } else {
        error.at_entry(name.to_vec(), operation)
    }
}

#[cfg(test)]
mod input_size_tests {
    use super::*;

    #[test]
    fn writer_adapters_flush_the_output_and_preserve_checksums() {
        struct FlushingSink {
            bytes: Vec<u8>,
            flushes: usize,
            fail: bool,
        }

        impl Write for FlushingSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.fail {
                    Err(std::io::Error::other("injected flush failure"))
                } else {
                    Ok(())
                }
            }
        }

        let mut output = FlushingSink {
            bytes: Vec::new(),
            flushes: 0,
            fail: false,
        };
        {
            let mut tee = Tee {
                output: &mut output,
                mirror: None,
            };
            tee.write_all(b"payload").unwrap();
            tee.flush().unwrap();
        }
        assert_eq!(output.bytes, b"payload");
        assert_eq!(output.flushes, 1);
        output.fail = true;
        assert_eq!(
            Tee {
                output: &mut output,
                mirror: None,
            }
            .flush()
            .unwrap_err()
            .to_string(),
            "injected flush failure"
        );
        assert_eq!(output.flushes, 2);

        let mut checksum = ChecksumSink::new(false);
        checksum.write_all(b"payload").unwrap();
        checksum.flush().unwrap();
        assert_eq!(checksum.crc.finish(), crate::crc32::crc32(b"payload"));
    }

    fn virtual_entry(name: &[u8], length: u64) -> ArchiveEntry {
        ArchiveEntry::new(
            name.to_vec(),
            crate::EntrySource::from_opener(length, || panic!("measuring input opened a source")),
        )
    }

    #[test]
    fn total_input_size_accepts_empty_and_exact_u64_maximum() {
        assert_eq!(total_input_size(&[]).unwrap(), 0);
        let entries = [
            virtual_entry(b"first", u64::MAX - 1),
            virtual_entry(b"last", 1),
            virtual_entry(b"empty", 0),
        ];
        assert_eq!(total_input_size(&entries).unwrap(), u64::MAX);
    }

    #[test]
    fn total_input_size_preserves_source_errors_and_cancellation() {
        struct Broken(bool);
        impl crate::streaming::SourceFactory for Broken {
            fn len(&self) -> Result<u64> {
                if self.0 {
                    Err(Error::Cancelled)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected metadata failure",
                    )
                    .into())
                }
            }
            fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
                panic!("measuring input opened a source")
            }
        }
        for cancelled in [false, true] {
            let entry = ArchiveEntry::new(
                b"broken".to_vec(),
                crate::EntrySource::from_factory(Broken(cancelled)),
            );
            let error = total_input_size(&[entry]).unwrap_err();
            if cancelled {
                assert_eq!(error, Error::Cancelled);
                assert!(error.entry_context().is_none());
            } else {
                assert_eq!(error.kind(), crate::ErrorKind::Io);
                assert_eq!(
                    error.entry_context().unwrap(),
                    (b"broken".as_slice(), "preparing")
                );
            }
        }
    }
}

#[cfg(all(test, feature = "encryption"))]
mod hashed_on_copy_tests {
    use super::super::{
        write_seekable_archive_to, write_streaming_archive_to, ArchiveExtras, WriterOptions,
    };
    use super::*;

    fn entries(password: Option<&[u8]>) -> Vec<ArchiveEntry> {
        [5000usize, 0, 33]
            .into_iter()
            .enumerate()
            .map(|(index, len)| {
                let data: Vec<u8> = (0..len).map(|at| (at * 7 + index) as u8).collect();
                let entry = ArchiveEntry::new(
                    format!("member{index}").into_bytes(),
                    crate::EntrySource::from_bytes(data),
                );
                match password {
                    Some(password) => entry.with_password(password.to_vec()),
                    None => entry,
                }
            })
            .collect()
    }

    #[test]
    fn encrypted_archives_match_the_streamed_ones_under_the_same_entropy() {
        let cases: [(bool, bool, Option<u64>); 4] = [
            (false, false, None),
            (true, false, None),
            (false, true, None),
            (true, false, Some(5)),
        ];
        for (header_encryption, quick_open, recovery) in cases {
            if recovery.is_some() && !cfg!(feature = "recovery") {
                continue;
            }
            let mut features = crate::FeatureSet::store_only();
            features.header_encryption = header_encryption;
            features.quick_open = quick_open;
            let options = WriterOptions::new(crate::ArchiveVersion::Rar50, features)
                .with_compression_level(0);
            let entries = entries(Some(b"secret"));
            let extras = ArchiveExtras::default().with_recovery_percent(recovery);
            let resources = WriterResources::default();
            let streamed = crate::entropy::seeded::with(|| {
                let mut output = Vec::new();
                write_streaming_archive_to(
                    &entries,
                    options,
                    extras.clone(),
                    &resources,
                    &mut output,
                )
                .unwrap();
                output
            });
            let seekable = crate::entropy::seeded::with(|| {
                let mut output = std::io::Cursor::new(Vec::new());
                write_seekable_archive_to(
                    &entries,
                    options,
                    extras.clone(),
                    &resources,
                    &mut output,
                )
                .unwrap();
                output.into_inner()
            });
            assert_eq!(
                seekable, streamed,
                "headers={header_encryption}, quick_open={quick_open}, recovery={recovery:?}"
            );
            let archive = crate::ArchiveReader::read_with_options(
                &seekable,
                crate::ArchiveReadOptions::with_password(b"secret"),
            )
            .unwrap();
            archive.test(Some(b"secret")).unwrap();
        }
    }
}

#[cfg(test)]
mod quick_open_tests {
    use super::*;

    #[test]
    fn streamed_records_match_buffered_encoding_at_vint_boundaries() {
        for distance in [0, 127, 128, 16383, 16384, u64::MAX] {
            for size in [0, 1, 123, 127, 128, 16383, 16384] {
                let header = vec![0xa5; size];
                let mut body = Vec::new();
                write_vint(&mut body, 0);
                write_vint(&mut body, distance);
                write_vint(&mut body, size as u64);
                body.extend_from_slice(&header);
                let mut framed = Vec::new();
                write_vint(&mut framed, body.len() as u64);
                framed.extend_from_slice(&body);
                let mut expected = crate::crc32::crc32(&framed).to_le_bytes().to_vec();
                expected.extend_from_slice(&framed);
                let mut actual = Vec::new();
                let mut crc = crate::crc32::Crc32::new();
                append_quick_open_entry(&mut actual, &mut crc, distance, &header).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(crc.finish(), crate::crc32::crc32(&actual));
            }
        }
    }
}

#[cfg(test)]
mod service_payload_tests {
    use super::*;

    #[test]
    fn prepared_services_borrow_input_and_stream_identical_ciphertext() {
        for size in [0usize, 1, 15, 16, 65535, 65536, 65537, 131089] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let plain = stored_service_block(b"CMT", &data, &[], None, &WriterResources::default())
                .unwrap();
            let Payload::Borrowed(borrowed) = plain.payload else {
                panic!("expected borrowed service")
            };
            assert_eq!(borrowed.as_ptr(), data.as_ptr());
            assert_eq!(borrowed.len(), data.len());
            #[cfg(feature = "encryption")]
            {
                let encrypted = encrypted_service_block(
                    b"CMT",
                    &data,
                    &[],
                    b"secret",
                    &mut WriteKeys::default(),
                    None,
                    &WriterResources::default(),
                )
                .unwrap();
                let Payload::Encrypted { plain, keys, iv } = &encrypted.payload else {
                    panic!("expected streaming encryption")
                };
                let PlainPayload::Borrowed(borrowed) = plain.as_ref() else {
                    panic!("expected borrowed plaintext")
                };
                assert_eq!(borrowed.as_ptr(), data.as_ptr());
                let mut expected = data.clone();
                expected.resize(size.div_ceil(16) * 16, 0);
                crate::crypto::rar50::Rar50Cipher::new(keys.key, *iv)
                    .encrypt_in_place(&mut expected)
                    .unwrap();
                assert_eq!(encrypted.payload_len, expected.len() as u64);
                let mut actual = Vec::new();
                write_payload(
                    encrypted.payload,
                    &mut actual,
                    &WriterResources::default(),
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(actual, expected, "service size {size}");
            }
        }
    }
}

#[cfg(test)]
mod preparation_name_tests {
    use super::*;
    #[test]
    fn allocation_free_target_length_preserves_rar50_mapping_rules() {
        for bytes in [
            b"plain".as_slice(),
            b"\xffinvalid",
            "é/名字".as_bytes(),
            "\u{e080}".as_bytes(),
            "\u{fffe}a\u{e080}\u{e0ff}é".as_bytes(),
            "\u{fffe}\u{fffe}".as_bytes(),
        ] {
            assert_eq!(
                decoded_rar50_name_len(bytes),
                crate::filename::decode_rar50(bytes).len()
            );
        }
    }
}

#[cfg(test)]
mod emission_ledger_tests {
    use super::*;
    use crate::codec::workspace::Allowance;

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn source_disappearing_at_compression_start_retains_member_context() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for volumes in [false, true] {
            let scratch = crate::scratch::case("source-disappears-before-compression");
            let path = scratch.join("source");
            std::fs::write(&path, b"payload").unwrap();
            let entries = [ArchiveEntry::new(
                b"missing.bin".to_vec(),
                crate::EntrySource::from_path(&path),
            )];
            let resources = WriterResources::new(128 * 1024 * 1024)
                .with_max_memory_bytes(128 * 1024 * 1024)
                .with_temp_dir(&*scratch);
            let removed = AtomicBool::new(false);
            let callback = |event: crate::WriteProgressEvent<'_>| {
                if matches!(
                    event,
                    crate::WriteProgressEvent::OperationStarted {
                        operation: crate::WriteOperation::Compression,
                        ..
                    }
                ) && !removed.swap(true, Ordering::Relaxed)
                {
                    std::fs::remove_file(&path).unwrap();
                }
            };
            let mut plan = plan(false);
            plan.progress = Some(ProgressReporter(&callback));
            let error = if volumes {
                let mut output = super::super::CollectedVolumes::new();
                let error = write_volumes(&entries, plan, 64, &mut output, &resources).unwrap_err();
                assert!(output.take().is_empty());
                error
            } else {
                let mut output = Vec::new();
                let error = write_archive(
                    &entries,
                    plan,
                    &resources,
                    CallerOutput::stream(&mut output),
                )
                .unwrap_err();
                assert!(output.is_empty());
                error
            };
            assert!(removed.load(Ordering::Relaxed));
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                error.entry_context(),
                Some((b"missing.bin".as_slice(), "compressing"))
            );
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(resources.managed_memory_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn zero_volume_payload_is_rejected_before_opening_a_sink() {
        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let mut sink = super::super::CollectedVolumes::new();
        let error = write_volumes(
            &entries,
            plan(false),
            0,
            &mut sink,
            &WriterResources::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn prepared_record_counts_include_empty_archives_comments_and_services() {
        // The aggregate bound uses distinct live storage for owned records.
        assert!(std::mem::size_of::<ArchiveEntry>() >= 2);
        assert!(std::mem::size_of::<super::super::ServiceEntry>() >= 2);
        for count in 0..=2 {
            for comment in [false, true] {
                let entries: Vec<_> = (0..count)
                    .map(|index| {
                        let entry = ArchiveEntry::new(
                            format!("file{index}").into_bytes(),
                            crate::EntrySource::from_bytes(b"payload".to_vec()),
                        );
                        if index == 1 {
                            entry.with_service(super::super::ServiceEntry::new(b"CMT", b"note"))
                        } else {
                            entry
                        }
                    })
                    .collect();
                let mut settings = plan(false);
                settings.compress.method = 0;
                settings.quick_open = false;
                settings.recovery_percent = None;
                if !comment {
                    settings.archive_comment = None;
                }
                let mut bytes = Vec::new();
                write_archive(
                    &entries,
                    settings,
                    &WriterResources::default(),
                    CallerOutput::stream(&mut bytes),
                )
                .unwrap();
                let archive = crate::ArchiveReader::read_owned(bytes).unwrap();
                let raw = archive.as_rar50().unwrap();
                assert_eq!(raw.files().count(), count);
                assert_eq!(
                    raw.services().count(),
                    1 + usize::from(comment) + usize::from(count == 2)
                );
                for index in 0..count {
                    assert_eq!(
                        archive
                            .read_member(format!("file{index}").as_bytes(), None)
                            .unwrap()
                            .unwrap(),
                        b"payload"
                    );
                }
            }
        }
    }

    #[test]
    fn compression_completion_cancellation_precedes_archive_and_volume_emission() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancelAtCompletion {
            armed: AtomicBool,
            cancelled: AtomicBool,
            finished: AtomicBool,
            emitted: AtomicBool,
        }
        impl crate::WriteProgress for CancelAtCompletion {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                use crate::{WriteOperation, WriteProgressEvent};
                match event {
                    WriteProgressEvent::OperationStarted {
                        operation: WriteOperation::Compression,
                        total_entries: Some(0),
                        ..
                    }
                    | WriteProgressEvent::EntryFinished {
                        operation: WriteOperation::Compression,
                        ..
                    } => self.armed.store(true, Ordering::Relaxed),
                    WriteProgressEvent::Advanced {
                        operation: WriteOperation::Compression,
                        ..
                    } if self.armed.load(Ordering::Relaxed) => {
                        self.cancelled.store(true, Ordering::Relaxed);
                    }
                    WriteProgressEvent::OperationFinished {
                        operation: WriteOperation::Compression,
                        ..
                    } => self.finished.store(true, Ordering::Relaxed),
                    WriteProgressEvent::OperationStarted {
                        operation: WriteOperation::Emission,
                        ..
                    } => self.emitted.store(true, Ordering::Relaxed),
                    _ => {}
                }
            }
            fn is_cancelled(&self) -> bool {
                self.cancelled.load(Ordering::Relaxed)
            }
        }
        for empty in [false, true] {
            for volumes in [false, true] {
                let scratch = crate::scratch::case("completion-cancellation");
                let resources = WriterResources::default().with_temp_dir(&*scratch);
                let progress = CancelAtCompletion {
                    armed: AtomicBool::new(false),
                    cancelled: AtomicBool::new(false),
                    finished: AtomicBool::new(false),
                    emitted: AtomicBool::new(false),
                };
                let entries = if empty {
                    Vec::new()
                } else {
                    vec![ArchiveEntry::new(
                        b"file".to_vec(),
                        crate::EntrySource::from_bytes(b"payload".to_vec()),
                    )]
                };
                let mut settings = plan(false);
                settings.archive_comment = None;
                settings.recovery_percent = None;
                settings.progress = Some(ProgressReporter(&progress));
                let error = if volumes {
                    let mut sink = super::super::CollectedVolumes::new();
                    let error =
                        write_volumes(&entries, settings, 1024, &mut sink, &resources).unwrap_err();
                    assert!(sink.take().is_empty());
                    error
                } else {
                    let mut output = Vec::new();
                    let error = write_archive(
                        &entries,
                        settings,
                        &resources,
                        CallerOutput::stream(&mut output),
                    )
                    .unwrap_err();
                    if empty {
                        assert!(output.is_empty());
                    } else {
                        // The member went out as it finished; the archive was
                        // never closed.
                        let mut end = Bytes::new(&resources);
                        write_end_header(&mut end, 0, &resources).unwrap();
                        assert!(!output.is_empty() && !output.ends_with(&end));
                    }
                    error
                };
                assert_eq!(error, Error::Cancelled);
                assert!(progress.armed.load(Ordering::Relaxed));
                assert!(progress.cancelled.load(Ordering::Relaxed));
                assert!(!progress.finished.load(Ordering::Relaxed));
                let wrote_member = !volumes && !empty;
                assert_eq!(progress.emitted.load(Ordering::Relaxed), wrote_member);
                assert_eq!(resources.workspace_in_use(), 0);
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn quick_open_skips_file_services_but_keeps_plain_comments() {
        let entry = ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )
        .with_service(super::super::ServiceEntry::new(b"CMT", b"file note"));
        let mut plan = plan(false);
        plan.quick_open = true;
        plan.recovery_percent = None;
        let mut bytes = Vec::new();
        write_archive(
            &[entry],
            plan,
            &WriterResources::default(),
            CallerOutput::stream(&mut bytes),
        )
        .unwrap();

        let archive = crate::ArchiveReader::read_owned(bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.locator().unwrap().quick_open_offset.is_some());
        let quick_open = raw
            .services()
            .find(|service| service.name == b"QO")
            .unwrap();
        let payload = quick_open.packed_data(raw).unwrap();
        fn vint(data: &[u8], cursor: &mut usize) -> usize {
            let mut value = 0usize;
            for shift in (0..70).step_by(7) {
                let byte = data[*cursor];
                *cursor += 1;
                value |= ((byte & 0x7f) as usize) << shift;
                if byte & 0x80 == 0 {
                    return value;
                }
            }
            panic!("invalid quick-open record length")
        }
        let mut cursor = 0;
        let mut records = 0;
        while cursor < payload.len() {
            cursor += 4; // Per-record CRC32.
            let body_len = vint(&payload, &mut cursor);
            cursor += body_len;
            assert!(cursor <= payload.len());
            records += 1;
        }
        // The plain archive comment and file are cached; the attached service is not.
        assert_eq!(records, 2);
        assert_eq!(
            archive.member_comment_at(0, None).unwrap(),
            Some(b"file note".to_vec())
        );
        assert_eq!(
            archive.read_member(b"file", None).unwrap().unwrap(),
            b"payload"
        );
    }

    struct FailingSink;
    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected emission failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn archive_emission_propagates_each_output_write_failure() {
        struct FailOnWrite {
            fail_at: usize,
            writes: usize,
        }
        impl Write for FailOnWrite {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                let call = self.writes;
                self.writes += 1;
                if call == self.fail_at {
                    Err(std::io::Error::other("injected output failure"))
                } else {
                    Ok(data.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let settings = || {
            let mut plan = plan(false);
            plan.recovery_percent = None;
            plan.quick_open = true;
            plan
        };
        let resources = WriterResources::default();
        let mut counting = FailOnWrite {
            fail_at: usize::MAX,
            writes: 0,
        };
        write_archive(
            &entries,
            settings(),
            &resources,
            CallerOutput::stream(&mut counting),
        )
        .unwrap();
        assert!(counting.writes >= 6);

        let mut member_failure = false;
        let mut archive_failure = false;
        for fail_at in 0..counting.writes {
            let mut sink = FailOnWrite { fail_at, writes: 0 };
            let error = write_archive(
                &entries,
                settings(),
                &resources,
                CallerOutput::stream(&mut sink),
            )
            .unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io, "write {fail_at}");
            assert_eq!(sink.writes, fail_at + 1);
            if error.entry_context() == Some((b"file".as_slice(), "writing")) {
                member_failure = true;
            } else {
                archive_failure = true;
            }
        }
        assert!(member_failure);
        assert!(archive_failure);
    }

    #[cfg(feature = "recovery")]
    #[test]
    fn a_volume_closes_before_its_recovery_record_stops_covering_it() {
        struct Unused;
        impl super::super::VolumeSink for Unused {
            fn start_volume(&mut self, _: u64) -> Result<Box<dyn super::super::VolumeOutput>> {
                unreachable!("sizing a volume writes nothing")
            }
            fn finish_volume(&mut self, _: u64, _: u64) -> Result<()> {
                unreachable!("sizing a volume writes nothing")
            }
        }
        let resources = WriterResources::default();
        let largest = crate::recovery::rar5::MAX_STREAMED_RECOVERY_PREFIX;
        for (volume_size, capped) in [(largest / 2, false), (2 * largest, true), (1 << 50, true)] {
            let mut sink = Unused;
            let mut writer = VolumeWriter {
                volume_size,
                solid: false,
                recovery_percent: Some(5),
                header_keys: None,
                progress: None,
                resources: &resources,
                sink: &mut sink,
                body: None,
                head_crypt_len: 0,
                fixed_len: 0,
                body_budget: None,
                fragments_in_volume: 0,
                volume_index: 0,
                trailing_producer: None,
                trailing_len: 0,
            };
            writer.start_volume().unwrap();
            let budget = writer.body_budget().unwrap();
            assert!(writer.fits(budget).unwrap());
            assert!(!writer.fits(budget + 1).unwrap());
            // The volume this budget closes is one the layout accepts.
            let inputs = writer.layout_inputs(0, 0, budget);
            let prefix = resolve_layout(&inputs, &resources)
                .unwrap()
                .recovery_prefix_len
                .unwrap();
            if capped {
                assert_eq!(prefix, largest, "volume size {volume_size}");
            } else {
                assert!(prefix < largest);
            }
        }
    }

    #[test]
    fn volume_emission_propagates_sink_failures_before_handoff() {
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct State {
            writes: usize,
            finishes: usize,
        }
        struct Sink {
            state: Arc<Mutex<State>>,
            fail_write: Option<usize>,
            fail_start: bool,
            fail_flush: bool,
            fail_finish: bool,
        }
        struct Volume {
            state: Arc<Mutex<State>>,
            fail_write: Option<usize>,
            fail_flush: bool,
        }
        impl Write for Volume {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let mut state = self.state.lock().unwrap();
                let call = state.writes;
                state.writes += 1;
                if self.fail_write == Some(call) {
                    Err(std::io::Error::other("injected volume write failure"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if self.fail_flush {
                    Err(std::io::Error::other("injected volume flush failure"))
                } else {
                    Ok(())
                }
            }
        }
        impl std::io::Seek for Volume {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("the RAR 5 writer does not seek"))
            }
        }
        impl super::super::VolumeSink for Sink {
            fn start_volume(&mut self, _: u64) -> Result<Box<dyn super::super::VolumeOutput>> {
                if self.fail_start {
                    return Err(std::io::Error::other("injected volume start failure").into());
                }
                Ok(Box::new(Volume {
                    state: self.state.clone(),
                    fail_write: self.fail_write,
                    fail_flush: self.fail_flush,
                }))
            }
            fn finish_volume(&mut self, _: u64, _: u64) -> Result<()> {
                self.state.lock().unwrap().finishes += 1;
                if self.fail_finish {
                    Err(std::io::Error::other("injected volume finish failure").into())
                } else {
                    Ok(())
                }
            }
        }

        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let settings = || {
            let mut plan = plan(false);
            plan.recovery_percent = None;
            plan
        };
        let resources = WriterResources::default();
        let make_sink = || Sink {
            state: Arc::new(Mutex::new(State::default())),
            fail_write: None,
            fail_start: false,
            fail_flush: false,
            fail_finish: false,
        };
        let mut success = make_sink();
        write_volumes(&entries, settings(), 4096, &mut success, &resources).unwrap();
        let writes = success.state.lock().unwrap().writes;
        assert!(writes >= 4);
        assert_eq!(success.state.lock().unwrap().finishes, 1);

        for fail_at in 0..writes {
            let mut sink = make_sink();
            sink.fail_write = Some(fail_at);
            let error =
                write_volumes(&entries, settings(), 4096, &mut sink, &resources).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io, "write {fail_at}");
            assert_eq!(sink.state.lock().unwrap().writes, fail_at + 1);
            assert_eq!(sink.state.lock().unwrap().finishes, 0);
        }
        for failure in 0..3 {
            let mut sink = make_sink();
            sink.fail_start = failure == 0;
            sink.fail_flush = failure == 1;
            sink.fail_finish = failure == 2;
            let error =
                write_volumes(&entries, settings(), 4096, &mut sink, &resources).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                sink.state.lock().unwrap().finishes,
                usize::from(failure == 2)
            );
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encryption_emission_counts_retained_preparation_and_releases_chunk() {
        let data = vec![7; 65537];
        for limit in [65536, 131072] {
            let ledger = Allowance::limited(limit);
            let resources = WriterResources::default().with_execution_allowance(ledger.clone());
            let retained = Bytes::zeroed(128, &resources).unwrap();
            for fail_sink in [false, true] {
                let keys = Rar50Keys::derive(
                    b"secret",
                    [1; 16],
                    crate::crypto::rar50::WRITE_KDF_COUNT_LOG,
                )
                .unwrap();
                let mut expected = data.clone();
                expected.resize(data.len().div_ceil(16) * 16, 0);
                crate::crypto::rar50::Rar50Cipher::new(keys.key, [2; 16])
                    .encrypt_in_place(&mut expected)
                    .unwrap();
                let payload = Payload::Encrypted {
                    plain: Owned::new(PlainPayload::Borrowed(&data), &resources).unwrap(),
                    keys,
                    iv: [2; 16],
                };
                let mut actual = Vec::new();
                let result = if fail_sink {
                    write_payload(payload, &mut FailingSink, &resources, None, None).map(drop)
                } else {
                    write_payload(payload, &mut actual, &resources, None, None).map(drop)
                };
                if limit == 65536 {
                    assert_eq!(result.unwrap_err().kind(), crate::ErrorKind::ResourceLimit);
                    assert!(actual.is_empty());
                } else if fail_sink {
                    assert!(result.is_err());
                } else {
                    result.unwrap();
                    assert_eq!(actual, expected);
                }
                assert_eq!(ledger.used(), 128);
                assert_eq!(resources.workspace_in_use(), 0);
            }
            drop(retained);
            assert_eq!(ledger.used(), 0);
        }
    }

    #[test]
    #[cfg(feature = "recovery")]
    fn recovery_emission_shares_ledger_in_resident_and_striped_modes() {
        let scratch = crate::scratch::case("recovery-emission-ledger");
        let data = vec![7; 131072];
        for estimated_limit in [16384, 8 * 1024 * 1024] {
            let base = WriterResources::new(estimated_limit).with_temp_dir(&*scratch);
            let mut prefix = Spool::create(&base).unwrap();
            prefix.write_all(&data).unwrap();
            let mut expected = Vec::new();
            write_recovery_service(10, &mut prefix, None, &base, None, &mut expected).unwrap();
            for limit in [131072, 8 * 1024 * 1024] {
                let ledger = Allowance::limited(limit);
                let resources = base.clone().with_execution_allowance(ledger.clone());
                let retained = Bytes::zeroed(128, &resources).unwrap();
                let mut actual = Vec::new();
                let result =
                    write_recovery_service(10, &mut prefix, None, &resources, None, &mut actual);
                if limit == 131072 {
                    assert_eq!(result.unwrap_err().kind(), crate::ErrorKind::ResourceLimit);
                    assert!(actual.is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(actual, expected);
                    let cancel = CancelRecovery {
                        cancelled: std::sync::atomic::AtomicBool::new(false),
                    };
                    let error = write_recovery_service(
                        10,
                        &mut prefix,
                        None,
                        &resources,
                        Some(ProgressReporter(&cancel)),
                        &mut Vec::new(),
                    )
                    .unwrap_err();
                    assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
                    assert_eq!(ledger.used(), 128);

                    assert!(write_recovery_service(
                        10,
                        &mut prefix,
                        None,
                        &resources,
                        None,
                        &mut FailingSink
                    )
                    .is_err());
                }
                assert_eq!(ledger.used(), 128);
                assert_eq!(resources.workspace_in_use(), 0);
                drop(retained);
                assert_eq!(ledger.used(), 0);
                // The caller's prefix survives; temporary parity and payload files do not.
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 1);
            }
            drop(prefix);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[cfg(feature = "recovery")]
    struct CancelRecovery {
        cancelled: std::sync::atomic::AtomicBool,
    }
    #[cfg(feature = "recovery")]
    impl crate::WriteProgress for CancelRecovery {
        fn report(&self, event: crate::WriteProgressEvent<'_>) {
            if matches!(
                event,
                crate::WriteProgressEvent::Advanced {
                    operation: crate::WriteOperation::Recovery,
                    ..
                }
            ) {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    fn plan<'a>(encrypted: bool) -> EnginePlan<'a> {
        let options = crate::codec::rar50::EncodeOptions::new(8).with_max_match_distance(131072);
        EnginePlan {
            compress: CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 131072,
                block_size: 4096,
                solid: false,
                method: 0,
                filter_policy: super::super::FilterPolicy::None,
                candidates: vec![options].into(),
                blake2sp: true,
            },
            recovery_percent: cfg!(feature = "recovery").then_some(10),
            header_encrypted: encrypted,
            header_password: encrypted.then_some(b"secret".as_slice()),
            archive_comment: Some(if encrypted {
                ArchiveCommentPlan::Encrypted {
                    data: b"comment",
                    password: b"secret",
                }
            } else {
                ArchiveCommentPlan::Plain(b"comment")
            }),
            archive_metadata: None,
            metadata_record: None,
            locked: false,
            quick_open: false,
            progress: None,
        }
    }

    #[test]
    fn volume_emission_reports_compression_completion() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let finished = AtomicBool::new(false);
        let report = |event: crate::WriteProgressEvent<'_>| {
            if matches!(
                event,
                crate::WriteProgressEvent::OperationFinished {
                    operation: crate::WriteOperation::Compression,
                    total_bytes: Some(7),
                    total_entries: Some(1),
                    ..
                }
            ) {
                finished.store(true, Ordering::Relaxed);
            }
        };
        let mut plan = plan(false);
        plan.progress = Some(ProgressReporter(&report));
        plan.recovery_percent = None;
        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let mut sink = super::super::CollectedVolumes::new();
        write_volumes(&entries, plan, 4096, &mut sink, &WriterResources::default()).unwrap();
        assert!(finished.load(Ordering::Relaxed));
        assert_eq!(sink.take().len(), 1);
    }

    #[test]
    fn an_existing_member_context_is_not_wrapped_again() {
        let original =
            Error::InvalidArgument("source changed").at_entry(b"file".to_vec(), "reading");
        let error = member_error(original, b"file", "writing");
        assert_eq!(error.entry_context(), Some((b"file".as_slice(), "reading")));
    }

    #[test]
    fn archive_and_volume_emission_keep_the_ledger_reusable() {
        let scratch = crate::scratch::case("archive-emission-ledger");
        for encrypted in crate::test_features::encryption_cases() {
            let mut entry = ArchiveEntry::new(
                b"payload".to_vec(),
                crate::EntrySource::from_bytes(vec![7; 16384]),
            );
            if encrypted {
                entry = entry.with_password(b"secret");
            }
            let entries = [entry];
            let base = WriterResources::default().with_temp_dir(&*scratch);
            let ledger = Allowance::limited(8 * 1024 * 1024);
            let resources = base.clone().with_execution_allowance(ledger.clone());
            let mut expected = Vec::new();
            write_archive(
                &entries,
                plan(encrypted),
                &base,
                CallerOutput::stream(&mut expected),
            )
            .unwrap();
            let mut actual = Vec::new();
            write_archive(
                &entries,
                plan(encrypted),
                &resources,
                CallerOutput::stream(&mut actual),
            )
            .unwrap();
            if !encrypted {
                assert_eq!(actual, expected);
            } else {
                assert_eq!(actual.len(), expected.len());
            }
            assert_eq!(ledger.used(), 0);
            assert!(write_archive(
                &entries,
                plan(encrypted),
                &resources,
                CallerOutput::stream(&mut FailingSink)
            )
            .is_err());
            assert_eq!(ledger.used(), 0);
            let mut expected = super::super::CollectedVolumes::new();
            write_volumes(&entries, plan(encrypted), 4096, &mut expected, &base).unwrap();
            let small = Allowance::limited(32768);
            let constrained = base.clone().with_execution_allowance(small.clone());
            assert_eq!(
                write_volumes(
                    &entries,
                    plan(encrypted),
                    4096,
                    &mut super::super::CollectedVolumes::new(),
                    &constrained,
                )
                .unwrap_err()
                .kind(),
                crate::ErrorKind::ResourceLimit
            );
            assert_eq!(small.used(), 0);
            let mut actual = super::super::CollectedVolumes::new();
            write_volumes(&entries, plan(encrypted), 4096, &mut actual, &resources).unwrap();
            let expected = expected.take();
            let actual = actual.take();
            assert!(actual.len() > 1);
            assert_eq!(actual.len(), expected.len());
            if !encrypted {
                assert_eq!(actual, expected);
            } else {
                assert_eq!(
                    actual.iter().map(Vec::len).collect::<Vec<_>>(),
                    expected.iter().map(Vec::len).collect::<Vec<_>>()
                );
            }
            assert_eq!(ledger.used(), 0);
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn archive_preparation_refusals_release_capacity_at_each_boundary() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            settings.quick_open = true;
            let mut output = Vec::new();
            match write_archive(
                &entries,
                settings,
                &resources,
                CallerOutput::stream(&mut output),
            ) {
                Ok(()) => {
                    assert!(!output.is_empty());
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded {
                        limit: actual_limit,
                        required,
                        ..
                    } => {
                        assert_eq!(*actual_limit, limit);
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(limit < 64 * 1024, "tiny archive used too much preparation");
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3, "the test must cross several admission sites");
    }

    #[test]
    fn volume_preparation_refusals_release_capacity_at_each_boundary() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut volumes = super::super::CollectedVolumes::new();
            match write_volumes(&entries, settings, 4096, &mut volumes, &resources) {
                Ok(()) => {
                    assert_eq!(volumes.take().len(), 1);
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded {
                        limit: actual_limit,
                        required,
                        ..
                    } => {
                        assert_eq!(*actual_limit, limit);
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(
                            limit < 1024 * 1024,
                            "tiny volumes used {limit} bytes of preparation"
                        );
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3, "the test must cross several admission sites");
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_archive_preparation_refusals_release_capacity() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(true);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut output = Vec::new();
            match write_archive(
                &entries,
                settings,
                &resources,
                CallerOutput::stream(&mut output),
            ) {
                Ok(()) => {
                    assert!(!output.is_empty());
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded { required, .. } => {
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(
                            limit < 64 * 1024,
                            "encrypted archive used too much preparation"
                        );
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3);
    }

    #[test]
    fn oversized_archive_metadata_is_refused_during_layout_before_output() {
        let name = vec![b'm'; 4096];
        let mut settings = plan(false);
        settings.archive_comment = None;
        settings.recovery_percent = None;
        settings.archive_metadata = Some(super::super::ArchiveMetadataEntry {
            name: Some(&name),
            creation_time: Some(1),
        });
        let resources = WriterResources::default().with_max_preparation_bytes(128);
        let mut output = Vec::new();
        let error = write_archive(&[], settings, &resources, CallerOutput::stream(&mut output))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded { limit: 128, .. }
        ));
        assert!(output.is_empty());
        drop(Records::<u8>::new(128, &resources).unwrap());
    }

    #[test]
    fn archive_service_preparation_failure_preserves_member_context() {
        for encrypted in crate::test_features::encryption_cases() {
            let mut service = super::super::ServiceEntry::new(b"CMT", b"note");
            if encrypted {
                service = service.with_password(b"secret");
            }
            let mut entry = ArchiveEntry::new(
                b"member".to_vec(),
                crate::EntrySource::from_bytes(b"payload".to_vec()),
            );
            for _ in 0..8 {
                entry = entry.with_service(service.clone());
            }
            let mut limit = 0;
            let mut service_refused = false;
            loop {
                let mut settings = plan(false);
                settings.archive_comment = None;
                settings.recovery_percent = None;
                let resources = WriterResources::default().with_max_preparation_bytes(limit);
                let mut output = Vec::new();
                let result = write_archive(
                    std::slice::from_ref(&entry),
                    settings,
                    &resources,
                    CallerOutput::stream(&mut output),
                );
                assert_eq!(resources.workspace_in_use(), 0);
                drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                match result {
                    Ok(()) => {
                        assert!(!output.is_empty());
                        assert!(service_refused);
                        break;
                    }
                    Err(error) => {
                        assert!(output.is_empty());
                        let Error::WriterPreparationLimitExceeded {
                            required,
                            limit: actual,
                            ..
                        } = error.root_cause()
                        else {
                            panic!("unexpected preparation failure: {error}");
                        };
                        assert_eq!(*actual, limit);
                        assert!(*required > limit);
                        service_refused |= error.entry_context()
                            == Some((b"member".as_slice(), "preparing service"));
                        limit = *required;
                        assert!(limit < 64 * 1024);
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_service_rejects_oversized_name_after_extra_preparation() {
        let name = vec![b'n'; 4096];
        let resources = WriterResources::default().with_max_preparation_bytes(512);
        let error = encrypted_service_block(
            &name,
            b"payload",
            &[],
            b"secret",
            &mut WriteKeys::default(),
            None,
            &resources,
        )
        .err()
        .expect("the service name exceeds the preparation quota");
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded { limit: 512, .. }
        ));
        drop(Records::<u8>::new(512, &resources).unwrap());
    }

    #[test]
    fn archive_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<Vec<u8>> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            settings.quick_open = true;
            let mut output = Vec::new();
            write_archive(
                &entries,
                settings,
                resources,
                CallerOutput::stream(&mut output),
            )?;
            Ok(output)
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(!run(&resources).unwrap().is_empty());
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn volumes_release_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<usize> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut volumes = super::super::CollectedVolumes::new();
            write_volumes(&entries, settings, 4096, &mut volumes, resources)?;
            Ok(volumes.take().len())
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert_eq!(run(&resources).unwrap(), 1);
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    #[cfg(feature = "recovery")]
    fn recovery_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<Vec<u8>> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            let mut output = Vec::new();
            write_archive(
                &entries,
                settings,
                resources,
                CallerOutput::stream(&mut output),
            )?;
            Ok(output)
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(!run(&resources).unwrap().is_empty());
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    #[cfg(feature = "recovery")]
    fn volume_recovery_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<usize> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            let mut volumes = super::super::CollectedVolumes::new();
            write_volumes(&entries, settings, 4096, &mut volumes, resources)?;
            Ok(volumes.take().len())
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(run(&resources).unwrap() > 0);
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(
            count < 200,
            "unexpectedly many preparation admissions: {count}"
        );
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_outputs_release_late_preparation_refusals() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        for volumes in [false, true] {
            let run = |resources: &WriterResources| -> Result<()> {
                let mut settings = plan(true);
                settings.compress.method = 0;
                settings.recovery_percent = None;
                settings.archive_comment = None;
                if volumes {
                    write_volumes(
                        &entries,
                        settings,
                        4096,
                        &mut super::super::CollectedVolumes::new(),
                        resources,
                    )
                } else {
                    write_archive(
                        &entries,
                        settings,
                        resources,
                        CallerOutput::stream(&mut Vec::new()),
                    )
                }
            };
            let (resources, attempts) =
                WriterResources::default().refuse_preparation_growth_at(usize::MAX);
            run(&resources).unwrap();
            let count = attempts.load(Ordering::Relaxed);
            assert!(count > 3);
            assert!(count < 200);
            assert_eq!(resources.preparation_in_use(), 0);

            for index in count - 3..count {
                let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
                let error = run(&resources).unwrap_err();
                assert_eq!(
                    error.root_cause(),
                    &Error::WriterFailure("injected preparation admission failure"),
                    "volume mode {volumes}, admission {index}"
                );
                assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
            }
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    #[cfg(feature = "recovery")]
    fn encrypted_recovery_releases_late_preparation_refusals() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        let run = |resources: &WriterResources| -> Result<()> {
            let mut settings = plan(true);
            settings.compress.method = 0;
            settings.archive_comment = None;
            write_archive(
                &entries,
                settings,
                resources,
                CallerOutput::stream(&mut Vec::new()),
            )
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        run(&resources).unwrap();
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 5);
        assert_eq!(resources.preparation_in_use(), 0);

        for index in count - 5..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_volume_reread_failure_keeps_member_context() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let opens = Arc::new(AtomicUsize::new(0));
        let source = crate::EntrySource::from_opener(8, {
            let opens = opens.clone();
            move || {
                if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(Box::new(std::io::Cursor::new(b"contents".to_vec())))
                } else {
                    Err(std::io::Error::other("injected encrypted reread failure").into())
                }
            }
        });
        let entries = [ArchiveEntry::new(b"payload".to_vec(), source).with_password(b"secret")];
        let mut settings = plan(false);
        settings.compress.method = 0;
        settings.archive_comment = None;
        settings.recovery_percent = None;
        let mut volumes = super::super::CollectedVolumes::new();
        let error = write_volumes(
            &entries,
            settings,
            4096,
            &mut volumes,
            &WriterResources::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(
            error.entry_context(),
            Some((b"payload".as_slice(), "preparing volume payload"))
        );
        assert_eq!(opens.load(Ordering::Relaxed), 2);
        assert!(volumes.take().is_empty());
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_compressed_volume_payload_propagates_spool_refusal() {
        let scratch = crate::scratch::case("encrypted-volume-spool-refusal");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let entry = ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(vec![b'A'; 64 * 1024]),
        )
        .with_password(b"secret");
        let mut settings = plan(false);
        settings.compress.method = 1;
        settings.recovery_percent = None;
        let member = compress::compress_members_reporting(
            std::slice::from_ref(&entry.source),
            settings.compress.clone(),
            &resources,
            &|_| true,
        )
        .unwrap()
        .remove(0);
        assert!(!member.store);

        let constrained = resources.clone().with_max_spool_bytes(0);
        let error = prepare_volume_member(
            &entry,
            member,
            &settings,
            &mut WriteKeys::default(),
            &constrained,
        )
        .err()
        .expect("encrypted ciphertext must be charged to its spool");
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod stored_pipe_tests {
    use super::super::{write_streaming_archive_to, ArchiveExtras, WriterOptions};
    use super::*;
    use std::io::SeekFrom;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn hashed() -> crate::FeatureSet {
        crate::FeatureSet {
            blake2sp: true,
            ..crate::FeatureSet::store_only()
        }
    }

    fn data(len: usize, seed: usize) -> Vec<u8> {
        (0..len)
            .map(|at| (at.wrapping_mul(31) ^ (at >> 9) ^ seed) as u8)
            .collect()
    }

    fn entries() -> Vec<ArchiveEntry> {
        [(2_500_000, 1), (0, 2), (70_000, 3)]
            .into_iter()
            .map(|(len, seed)| {
                ArchiveEntry::new(
                    format!("member{seed}").into_bytes(),
                    crate::EntrySource::from_bytes(data(len, seed)),
                )
            })
            .collect()
    }

    fn store(features: crate::FeatureSet) -> WriterOptions {
        WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(0)
    }

    fn piped(entries: &[ArchiveEntry], options: WriterOptions, extras: ArchiveExtras) -> Vec<u8> {
        let mut output = Vec::new();
        write_streaming_archive_to(
            entries,
            options,
            extras,
            &WriterResources::default(),
            &mut output,
        )
        .unwrap();
        output
    }

    fn fingerprint(bytes: &[u8]) -> String {
        let hash = crate::rar50::blake2sp::hash(bytes);
        let hex: String = hash[..8].iter().map(|byte| format!("{byte:02x}")).collect();
        format!("{}:{hex}", bytes.len())
    }

    #[test]
    fn stored_pipe_archives_match_fingerprints_captured_from_master() {
        let entries = entries();
        // Captured when every member carried a BLAKE2sp hash, which is what
        // asking for one still writes, byte for byte.
        let plain = hashed();
        let mut quick_open = plain;
        quick_open.quick_open = true;
        let mut cases = Vec::new();
        cases.extend([
            (
                "crc32_only",
                piped(
                    &entries,
                    store(crate::FeatureSet::store_only()),
                    ArchiveExtras::default(),
                ),
            ),
            (
                "one",
                piped(&entries[..1], store(plain), ArchiveExtras::default()),
            ),
            (
                "empty",
                piped(&entries[1..2], store(plain), ArchiveExtras::default()),
            ),
            (
                "several",
                piped(&entries, store(plain), ArchiveExtras::default()),
            ),
            (
                "quick_open",
                piped(&entries, store(quick_open), ArchiveExtras::default()),
            ),
        ]);
        #[cfg(feature = "recovery")]
        cases.push((
            "recovery",
            piped(
                &entries,
                store(plain),
                ArchiveExtras::default().with_recovery_percent(Some(5)),
            ),
        ));
        #[cfg(feature = "encryption")]
        {
            let locked: Vec<ArchiveEntry> = entries
                .iter()
                .cloned()
                .map(|entry| entry.with_password(b"secret".to_vec()))
                .collect();
            let mut headers = plain;
            headers.header_encryption = true;
            cases.push((
                "encrypted",
                crate::entropy::seeded::with(|| {
                    piped(&locked, store(plain), ArchiveExtras::default())
                }),
            ));
            cases.push((
                "encrypted_headers",
                crate::entropy::seeded::with(|| {
                    piped(&locked, store(headers), ArchiveExtras::default())
                }),
            ));
        }
        let expected = [
            ("crc32_only", "2570159:a0e203b26c17284a"),
            ("one", "2500141:214930c9491ae64f"),
            ("empty", "135:48c92c5a1d765e8b"),
            ("several", "2570267:4b7664377148b4e7"),
            ("quick_open", "2570524:8e585393f60e0b4d"),
            ("recovery", "2715543:e2c41f112ff34c56"),
            ("encrypted", "2570414:095fdfd7c4ea3e13"),
            ("encrypted_headers", "2570602:6261c6bdeaa4b8b7"),
        ];
        let actual: Vec<_> = cases
            .iter()
            .map(|(name, bytes)| (*name, fingerprint(bytes)))
            .collect();
        for (name, fingerprint) in &actual {
            let (_, want) = expected.iter().find(|(case, _)| case == name).unwrap();
            assert_eq!(fingerprint, want, "{name}: {actual:?}");
        }
    }

    fn seekable(
        entries: &[ArchiveEntry],
        options: WriterOptions,
        extras: ArchiveExtras,
    ) -> Vec<u8> {
        let mut output = std::io::Cursor::new(Vec::new());
        super::super::write_seekable_archive_to(
            entries,
            options,
            extras,
            &WriterResources::default(),
            &mut output,
        )
        .unwrap();
        output.into_inner()
    }

    #[test]
    fn stored_seekable_archives_match_fingerprints_captured_before_the_pipelined_copy() {
        let entries = entries();
        let plain = hashed();
        let mut quick_open = plain;
        quick_open.quick_open = true;
        let mut cases = Vec::new();
        cases.extend([
            (
                "crc32_only".to_string(),
                seekable(
                    &entries,
                    store(crate::FeatureSet::store_only()),
                    ArchiveExtras::default(),
                ),
            ),
            (
                "one".to_string(),
                seekable(&entries[..1], store(plain), ArchiveExtras::default()),
            ),
            (
                "several".to_string(),
                seekable(&entries, store(plain), ArchiveExtras::default()),
            ),
            (
                "quick_open".to_string(),
                seekable(&entries, store(quick_open), ArchiveExtras::default()),
            ),
        ]);
        #[cfg(feature = "recovery")]
        cases.push((
            "recovery".to_string(),
            seekable(
                &entries,
                store(plain),
                ArchiveExtras::default().with_recovery_percent(Some(5)),
            ),
        ));
        let cases: Vec<_> = cases
            .into_iter()
            .map(|(name, bytes)| (name, crate::write_stream::fingerprint([&bytes[..]])))
            .collect();
        let expected = [
            ("crc32_only", "2570159:30ddf3ad"),
            ("one", "2500141:a6c68802"),
            ("several", "2570267:a6dc6e09"),
            ("quick_open", "2570524:d5eb5a67"),
            ("recovery", "2715543:c207e3f3"),
        ];
        crate::write_stream::assert_fingerprints(&cases, &expected);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_header_archives_match_fingerprints_captured_from_master() {
        use super::super::{write_seekable_archive_to, write_streaming_volumes_to};
        let locked: Vec<ArchiveEntry> = entries()
            .into_iter()
            .map(|entry| entry.with_password(b"secret".to_vec()))
            .collect();
        let mut headers = hashed();
        headers.header_encryption = true;
        let seekable = crate::entropy::seeded::with(|| {
            let mut output = std::io::Cursor::new(Vec::new());
            write_seekable_archive_to(
                &locked,
                store(headers),
                ArchiveExtras::default(),
                &WriterResources::default(),
                &mut output,
            )
            .unwrap();
            output.into_inner()
        });
        let mut sink = crate::volume_sink::CollectedVolumes::new();
        crate::entropy::seeded::with(|| {
            write_streaming_volumes_to(
                &locked,
                store(headers),
                ArchiveExtras::default(),
                1_000_000,
                &mut sink,
                &WriterResources::default(),
            )
        })
        .unwrap();
        let cases = [
            (
                "seekable".to_string(),
                crate::write_stream::fingerprint([&seekable[..]]),
            ),
            (
                "volumes".to_string(),
                crate::write_stream::fingerprint(sink.take().iter().map(Vec::as_slice)),
            ),
        ];
        let expected = [
            ("seekable", "2570602:d156fdb9"),
            (
                "volumes",
                "1000000:2813d873 1000000:a39861c1 571262:ce3e9274",
            ),
        ];
        crate::write_stream::assert_fingerprints(&cases, &expected);
    }

    struct Counting {
        inner: std::io::Cursor<Vec<u8>>,
        reads: Arc<AtomicUsize>,
    }

    impl Read for Counting {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(buffer)
        }
    }

    impl Seek for Counting {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn both_stored_pipe_passes_read_a_large_member_in_mebibyte_blocks() {
        let bytes = data(3 * 1024 * 1024, 0);
        let reads = Arc::new(AtomicUsize::new(0));
        let source = {
            let (bytes, reads) = (bytes.clone(), reads.clone());
            crate::EntrySource::from_opener(bytes.len() as u64, move || {
                Ok(Box::new(Counting {
                    inner: std::io::Cursor::new(bytes.clone()),
                    reads: reads.clone(),
                }))
            })
        };
        let archive = piped(
            &[ArchiveEntry::new(b"large".to_vec(), source)],
            store(crate::FeatureSet::store_only()),
            ArchiveExtras::default(),
        );
        // Three blocks and an end-of-source probe per pass; 64 KiB and 8 KiB
        // blocks took 48 and 384.
        let reads = reads.load(Ordering::SeqCst);
        assert!(reads <= 10, "{reads} reads");
        let archive = crate::ArchiveReader::read_owned(archive).unwrap();
        assert_eq!(archive.read_member(b"large", None).unwrap().unwrap(), bytes);
    }
}

#[cfg(test)]
mod stored_copy_pipeline_tests {
    use super::super::{
        write_seekable_archive_with_progress, write_streaming_archive_with_progress, ArchiveExtras,
        WriterOptions,
    };
    use super::*;
    use crate::atomic64::AtomicU64;
    use std::io::SeekFrom;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::ThreadId;

    #[derive(Default)]
    struct Opening {
        threads: Mutex<Vec<ThreadId>>,
        served: AtomicU64,
    }

    struct Traced {
        len: u64,
        at: u64,
        opening: Arc<Opening>,
    }

    impl Read for Traced {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.opening
                .threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            let count = (self.len - self.at).min(buffer.len() as u64) as usize;
            buffer[..count].fill((self.at % 251) as u8);
            self.at += count as u64;
            self.opening
                .served
                .fetch_add(count as u64, Ordering::Relaxed);
            Ok(count)
        }
    }

    impl Seek for Traced {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.at = match position {
                SeekFrom::Start(at) => at,
                SeekFrom::Current(by) => self.at.saturating_add_signed(by),
                SeekFrom::End(by) => self.len.saturating_add_signed(by),
            };
            Ok(self.at)
        }
    }

    fn traced(len: u64) -> (crate::EntrySource, Arc<Mutex<Vec<Arc<Opening>>>>) {
        let openings = Arc::new(Mutex::new(Vec::new()));
        let opened = openings.clone();
        let source = crate::EntrySource::from_opener(len, move || {
            let opening = Arc::new(Opening::default());
            opened.lock().unwrap().push(opening.clone());
            Ok(Box::new(Traced {
                len,
                at: 0,
                opening,
            }))
        });
        (source, openings)
    }

    fn write(
        source: crate::EntrySource,
        seekable: bool,
        progress: Option<&dyn crate::WriteProgress>,
        resources: &WriterResources,
        output: &mut (impl Write + Seek),
    ) -> Result<()> {
        let options = WriterOptions::new(
            crate::ArchiveVersion::Rar50,
            crate::FeatureSet::store_only(),
        )
        .with_compression_level(0);
        let entries = [ArchiveEntry::new(b"member".to_vec(), source)];
        if seekable {
            write_seekable_archive_with_progress(
                &entries,
                options,
                ArchiveExtras::default(),
                resources,
                progress,
                output,
            )
        } else {
            write_streaming_archive_with_progress(
                &entries,
                options,
                ArchiveExtras::default(),
                resources,
                progress,
                output,
            )
        }
    }

    fn copy_read_on_caller(len: u64, seekable: bool, resources: &WriterResources) -> bool {
        let (source, openings) = traced(len);
        write(
            source,
            seekable,
            None,
            resources,
            &mut std::io::Cursor::new(Vec::new()),
        )
        .unwrap();
        let caller = std::thread::current().id();
        // A pipe's pre-pass opens the source first; the last opening is the copy's.
        let copy = openings.lock().unwrap().last().unwrap().clone();
        let threads = copy.threads.lock().unwrap();
        threads.iter().all(|thread| *thread == caller)
    }

    #[test]
    fn large_members_are_copied_off_the_caller_unless_it_may_not_spawn() {
        let unlimited = WriterResources::default();
        // Room for the inline copy's block, not for the pipeline's four.
        let tight = WriterResources::default().with_max_preparation_bytes(3 << 20);
        for seekable in [false, true] {
            if crate::parallel::may_spawn() {
                assert!(
                    !copy_read_on_caller(4 << 20, seekable, &unlimited),
                    "seekable={seekable}"
                );
            }
            assert!(
                copy_read_on_caller(256 << 10, seekable, &unlimited),
                "seekable={seekable}"
            );
            assert!(
                copy_read_on_caller(4 << 20, seekable, &tight),
                "seekable={seekable}"
            );
            let _cap = crate::parallel::ThreadCap::set(Some(1));
            assert!(
                copy_read_on_caller(4 << 20, seekable, &unlimited),
                "seekable={seekable}"
            );
        }
    }

    struct Output {
        inner: std::io::Cursor<Vec<u8>>,
        room: u64,
        fail: bool,
        full: Arc<AtomicBool>,
    }

    impl Write for Output {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.inner.position() + buffer.len() as u64 > self.room {
                self.full.store(true, Ordering::Relaxed);
                if self.fail {
                    return Err(std::io::Error::other("disk full"));
                }
            }
            self.inner.write(buffer)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for Output {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    struct CancelWhenFull(Arc<AtomicBool>);

    impl crate::WriteProgress for CancelWhenFull {
        fn report(&self, _: crate::WriteProgressEvent<'_>) {}
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn a_failing_or_cancelled_output_stops_reading_the_member() {
        for seekable in [false, true] {
            for fail in [true, false] {
                let (source, openings) = traced(64 << 20);
                let full = Arc::new(AtomicBool::new(false));
                let mut output = Output {
                    inner: std::io::Cursor::new(Vec::new()),
                    room: 5 << 20,
                    fail,
                    full: full.clone(),
                };
                let progress = CancelWhenFull(full);
                let progress = (!fail).then_some(&progress as &dyn crate::WriteProgress);
                let error = write(
                    source,
                    seekable,
                    progress,
                    &WriterResources::default(),
                    &mut output,
                )
                .unwrap_err();
                let case = format!("seekable={seekable}, fail={fail}: {error}");
                if fail {
                    assert_eq!(error.kind(), crate::ErrorKind::Io, "{case}");
                    assert!(error.to_string().contains("disk full"), "{case}");
                } else {
                    assert_eq!(error.kind(), crate::ErrorKind::Cancelled, "{case}");
                }
                let copy = openings.lock().unwrap().last().unwrap().clone();
                let served = copy.served.load(Ordering::Relaxed);
                assert!(served < 16 << 20, "{case}: {served} bytes read");
            }
        }
    }
}
