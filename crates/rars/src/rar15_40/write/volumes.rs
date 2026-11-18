use super::*;
use crate::crc32::crc32_combine;
use crate::volume_sink::VolumeSink;
use std::io::{Read, Seek, SeekFrom};

/// A multiple of the cipher block, so only the last piece is ever padded.
const STREAM_CHUNK: usize = 64 * 1024;

/// Splits a stored member across volumes as it reads, so neither it nor the set is held.
pub fn write_stored_volumes_to(
    entry: &StreamingEntry,
    options: WriterOptions,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    let mut member = Member::from_streaming(entry);
    // This entry point predates directory members and has always written a file.
    member.is_directory = false;
    split_members(
        &[member],
        options,
        &MemberCoding::Stored,
        None,
        volume_size,
        sink,
        resources,
        progress,
    )
}

/// Packs members into one set in order, so one can end mid-volume and the next start there.
pub fn write_volumes_to(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    write_volumes_with_comment_to(
        entries,
        options,
        coding,
        None,
        volume_size,
        sink,
        resources,
        progress,
    )
}

/// The comment goes in the first volume only, as RAR writes it.
#[allow(clippy::too_many_arguments)]
pub fn write_volumes_with_comment_to(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    split_members(
        &members,
        options,
        &coding,
        archive_comment,
        volume_size,
        sink,
        resources,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn split_members(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: &MemberCoding,
    archive_comment: Option<&[u8]>,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    split_members_above(
        members,
        options,
        coding,
        archive_comment,
        volume_size,
        sink,
        resources,
        progress,
        STREAM_MEMBERS_ABOVE,
    )
}

/// Members larger than `stream_above` are coded into the volumes as they are read.
#[allow(clippy::too_many_arguments)]
pub(super) fn split_members_above(
    members: &[Member<'_>],
    mut options: WriterOptions,
    coding: &MemberCoding,
    archive_comment: Option<&[u8]>,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    stream_above: u64,
) -> Result<()> {
    let control =
        crate::write_progress::ResourceProgress::new(resources, progress.map(ProgressReporter));
    let progress = ProgressReporter(&control);
    crate::write_progress::check_cancelled(Some(progress))?;
    validate_plan(
        options,
        coding.shape().volumes(true),
        archive_comment.is_some(),
        false,
    )?;
    if let MemberCoding::Filtered(policy) = coding {
        validate_rar29_filter_policy(policy, options.method)?;
    }
    let compresses = coding.compresses();
    let mut total_bytes = 0u64;
    let mut largest_member = 0u64;
    for member in members {
        let len = member.unpacked_size().map_err(|error| {
            crate::write_stream::member_error(error, member.name, "reading source")
        })?;
        // Compressed set members still keep to 32-bit sizes, streamed or not.
        let validate = if compresses {
            validate_volume_member
        } else {
            validate_member
        };
        validate(member.name, options.target, len).map_err(|error| {
            crate::write_stream::member_error(error, member.name, "preparing volume member")
        })?;
        if member.file_comment.is_some() {
            return Err(Error::UnsupportedFeature {
                version: options.target,
                feature: "volume_file_comment",
            });
        }
        total_bytes = total_bytes.saturating_add(len);
        largest_member = largest_member.max(len);
    }
    let header_password = if options.features.header_encryption {
        validate_header_encrypted_archive_options(
            options.target,
            members.iter().any(|member| member.password.is_some()),
        )?;
        Some(header_encryption_password(
            members.iter().map(|member| member.password),
        )?)
    } else {
        None
    };
    let header_key = std::cell::OnceCell::new();
    let mut data_keys = DataKeys::default();
    if total_bytes == 0 {
        let error =
            Error::InvalidArgument("RAR 1.5 volume writer needs a non-empty packed payload");
        return Err(match members {
            [only] => error.at_entry(only.name.to_vec(), "preparing volume member"),
            _ => Error::InvalidArgument("legacy volume set has no member data to split"),
        });
    }
    if volume_size == 0 {
        return Err(Error::InvalidArgument("volume size must be non-zero"));
    }
    let solid = options.features.solid && compresses;
    if compresses && options.dictionary_size.is_none() {
        // A solid run is one stream, so its window reaches back across members.
        let reach = if solid { total_bytes } else { largest_member };
        options.dictionary_size = Some(fitted_dictionary_size(options.target, reach));
    }

    let operation = if compresses {
        WriteOperation::Compression
    } else {
        WriteOperation::Emission
    };
    // RAR 2.0 walks a non-solid member twice, once to pick a method and once to encode it.
    let total_work = if compresses && options.target == ArchiveVersion::Rar20 && !solid {
        total_bytes.saturating_mul(2)
    } else {
        total_bytes
    };
    progress.report(WriteProgressEvent::OperationStarted {
        operation,
        total_bytes: Some(total_work),
        total_entries: Some(members.len()),
        pass: 1,
    });
    let work = WorkTracker::new(Some(progress), operation, total_work);
    let mut solid_encoder = if solid {
        Some(SolidEncoder::for_target(options)?)
    } else {
        None
    };
    let mut solid_run_has_member = false;
    // Opened once the first member's key is derived, so a bad password names the member.
    let mut packer = None;
    let mut sink = Some(sink);
    let reserves = if writes_end_block(options.target) {
        vec![0; members.len()]
    } else {
        boundary_reserves(members, options.target)?
    };
    let mut open_packer = |name: &[u8]| -> Result<VolumePacker<'_>> {
        if let Some(password) = header_password {
            let key = HeaderKey::derive(password).map_err(|error| {
                crate::write_stream::member_error(error, name, "encrypting volume member")
            })?;
            let _ = header_key.set(key);
        }
        let comment = encode_archive_comment(
            archive_comment,
            options,
            header_key.get(),
            header_comment_password(options.target, header_password),
            &mut DataKeys::default(),
        )?;
        VolumePacker::new(
            sink.take().expect("the packer opens once"),
            volume_size as u64,
            options.target,
            if solid { MHD_SOLID } else { 0 },
            comment,
            header_key.get(),
            progress,
        )
    };
    for (member, &reserve) in members.iter().zip(&reserves) {
        let name = member.name;
        let streams = compresses
            && streams_member(member, options, coding, stream_above).map_err(|error| {
                crate::write_stream::member_error(error, name, "preparing volume member")
            })?;
        if streams {
            let packer = match &mut packer {
                Some(packer) => packer,
                None => packer.insert(open_packer(name)?),
            };
            let method = stream_member_into(
                packer,
                member,
                options,
                coding,
                &mut data_keys,
                solid.then_some(SolidLink {
                    encoder: &mut solid_encoder,
                    continues: solid_run_has_member,
                }),
                resources,
                &work,
            )
            .map_err(|error| {
                crate::write_stream::member_error(error, name, "compressing volume member")
            })?;
            // A streamed member is never empty, so only storing it ends the run.
            solid_run_has_member = method != 0x30;
            continue;
        }
        let encoded = if compresses && !member.is_directory {
            Some(
                encode_member(
                    member,
                    options,
                    coding,
                    &mut solid_encoder,
                    resources,
                    &work,
                )
                .map_err(|error| {
                    crate::write_stream::member_error(error, name, "compressing volume member")
                })?,
            )
        } else {
            None
        };
        let (packed, unpacked_size, method, final_crc) = match encoded {
            Some(EncodedMember {
                payload: MemberPayload::Packed(packed),
                method,
                unpacked_size,
                file_crc,
            }) => (Some(packed), unpacked_size, method, Some(file_crc)),
            Some(_) => {
                return Err(Error::WriterFailure(
                    "compressed volume member came back uncoded",
                ))
            }
            None => {
                let len = member.unpacked_size()?;
                if member.is_directory && len != 0 {
                    return Err(crate::write_stream::member_error(
                        Error::InvalidArgument("directory source must be empty"),
                        name,
                        "preparing volume member",
                    ));
                }
                (None, len, 0x30, None)
            }
        };
        let packed_bytes = packed.as_deref().map(MemberBytes::Borrowed);
        let bytes = packed_bytes.as_ref().unwrap_or(&member.bytes);
        // Chained as the plain writer chains them: see `solid_chain_runs_on`.
        let solid_continuation =
            solid && (method != 0x30 || member.is_directory) && solid_run_has_member;
        solid_run_has_member = solid_chain_runs_on(
            solid_run_has_member,
            member.is_directory,
            method,
            unpacked_size,
            packed.as_ref().is_some_and(|data| !data.is_empty()),
        );
        let cipher =
            CipherPlan::new(options.target, member.password, &mut data_keys).map_err(|error| {
                crate::write_stream::member_error(error, name, "encrypting volume member")
            })?;
        let packed_source_len = bytes.len()?;
        let packed_len = cipher.packed_len(packed_source_len)?;
        let stored_work = (!compresses).then_some(&work);
        let payload = PackedStream::open(bytes, packed_source_len, &cipher, progress, stored_work)
            .map_err(|error| {
                crate::write_stream::member_error(error, name, "encrypting volume member")
            })?;
        let volume_member = VolumeMember {
            head: FragmentHead {
                name,
                target: options.target,
                unpacked_size,
                file_time: member.file_time,
                file_attr: member.file_attr,
                host_os: member.host_os,
                method,
                dictionary_flags: if member.is_directory && options.target != ArchiveVersion::Rar15
                {
                    FHD_DIRECTORY_MASK
                } else {
                    dictionary_flags_for_options(options)?
                },
                file_flags: writer_file_flags(member.password, None, solid_continuation)
                    | if cipher.salt().is_some() { FHD_SALT } else { 0 },
                salt: cipher.salt(),
            },
            packed_len,
            final_crc,
            payload,
        };
        if packer.is_none() {
            let mut opened = open_packer(name)?;
            if members.len() == 1 {
                opened.expect_only(&volume_member)?;
            }
            packer = Some(opened);
        }
        packer
            .as_mut()
            .expect("opened above")
            .write_member(volume_member, reserve)?;
    }
    packer.expect("a set with data has a member").finish()?;
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    progress.report(WriteProgressEvent::OperationFinished {
        operation,
        total_bytes: Some(total_work),
        total_entries: Some(members.len()),
        pass: 1,
    });
    crate::write_progress::check_cancelled(Some(progress))
}

/// RAR 1.5 and 2.0 volumes have no end block, so a reader moves to the next
/// volume only when the last member in one continues there. Each entry is the
/// room to leave after that member's last byte so the next member with data
/// starts in the same volume; empty members between them have no data to
/// split, so their headers are counted too.
fn boundary_reserves(members: &[Member<'_>], target: ArchiveVersion) -> Result<Vec<u64>> {
    let mut reserves = vec![0u64; members.len()];
    for index in (0..members.len().saturating_sub(1)).rev() {
        let next = &members[index + 1];
        let header = header_len_bound(next, target)?;
        reserves[index] = if next.unpacked_size()? == 0 {
            header.saturating_add(reserves[index + 1])
        } else {
            header.saturating_add(1)
        };
    }
    Ok(reserves)
}

/// At least the length of a member's RAR 1.5 or 2.0 file header, which has no
/// salt: only the name and whether the sizes need high words change it.
fn header_len_bound(member: &Member<'_>, target: ArchiveVersion) -> Result<u64> {
    let unpacked_size = member.unpacked_size()?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: member.name,
            unpacked_size,
            file_crc: 0,
            // Coding or cipher padding can make the packed size the larger.
            packed_size: unpacked_size.saturating_add(64),
            file_time: 0,
            file_attr: 0,
            host_os: 0,
            target,
            method: 0x30,
            dictionary_flags: 0,
            flags: 0,
            salt: None,
            extra: &[],
        },
    )?;
    Ok(header.len() as u64)
}

/// What every fragment header of a member says, apart from the fragment's size and CRC.
struct FragmentHead<'a> {
    name: &'a [u8],
    target: ArchiveVersion,
    unpacked_size: u64,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    method: u8,
    dictionary_flags: u16,
    file_flags: u16,
    salt: Option<[u8; 8]>,
}

impl FragmentHead<'_> {
    fn header(
        &self,
        split_before: bool,
        split_after: bool,
        packed_size: u64,
        file_crc: u32,
        header_key: Option<&HeaderKey>,
    ) -> Result<Vec<u8>> {
        let mut flags = self.file_flags;
        if split_before {
            flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= FHD_SPLIT_AFTER;
        }
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            &FileRecord {
                head_type: FILE_HEAD,
                name: self.name,
                unpacked_size: self.unpacked_size,
                file_crc,
                packed_size,
                file_time: self.file_time,
                file_attr: self.file_attr,
                host_os: self.host_os,
                target: self.target,
                method: self.method,
                dictionary_flags: self.dictionary_flags,
                flags,
                salt: self.salt,
                extra: &[],
            },
        )?;
        match header_key {
            Some(key) => {
                let mut out = Vec::new();
                write_encrypted_header(&mut out, &header, key)?;
                Ok(out)
            }
            None => Ok(header),
        }
    }
}

/// A member's header fields and a reader over its packed bytes.
struct VolumeMember<'a> {
    head: FragmentHead<'a>,
    packed_len: u64,
    /// Known when packing worked it out; otherwise found while copying the payload.
    final_crc: Option<u32>,
    payload: PackedStream<'a>,
}

/// A fragment just written behind its placeholder header.
struct Fragment {
    header_len: u64,
    continued: bool,
    split_after: bool,
    len: u64,
    crc: u32,
}

/// Packs members into volumes; end blocks wait for the close, when it is known whether more follow.
struct VolumePacker<'a> {
    sink: &'a mut dyn VolumeSink,
    volume_size: u64,
    target: ArchiveVersion,
    /// Flags beyond the volume ones every main header carries, such as solid.
    main_flags: u16,
    /// Built once, so every look at the first volume's head sees the same salt.
    comment: Vec<u8>,
    header_key: Option<&'a HeaderKey>,
    progress: ProgressReporter<'a>,
    tail_len: u64,
    open: Option<OpenVolume>,
    index: u64,
    total_volumes: Option<usize>,
}

struct OpenVolume {
    out: Box<dyn crate::volume_sink::VolumeOutput>,
    used: u64,
    fragments: u64,
    /// The last fragment in it finishes its member.
    ends_member: bool,
    /// CRC32 of the volume's bytes so far, as they end up once headers are patched.
    crc: u32,
}

impl<'a> VolumePacker<'a> {
    fn new(
        sink: &'a mut dyn VolumeSink,
        volume_size: u64,
        target: ArchiveVersion,
        main_flags: u16,
        comment: Vec<u8>,
        header_key: Option<&'a HeaderKey>,
        progress: ProgressReporter<'a>,
    ) -> Result<Self> {
        let mut packer = Self {
            sink,
            volume_size,
            target,
            main_flags,
            comment,
            header_key,
            progress,
            tail_len: 0,
            open: None,
            index: 0,
            total_volumes: None,
        };
        packer.tail_len = packer.tail(0, false, 0)?.len() as u64;
        Ok(packer)
    }

    /// Works out the set's size up front when `member` is the only one.
    fn expect_only(&mut self, member: &VolumeMember<'_>) -> Result<()> {
        let header_len = self
            .header_len(&member.head, member.packed_len)
            .map_err(|error| {
                crate::write_stream::member_error(error, member.head.name, "writing volume member")
            })?;
        let overhead = self.head(0)?.len() as u64 + header_len + self.tail_len;
        if let Some(payload) = self.volume_size.checked_sub(overhead).filter(|&p| p > 0) {
            let total = member.packed_len.div_ceil(payload);
            self.sink.expect_volumes(total)?;
            self.total_volumes = usize::try_from(total).ok();
        }
        Ok(())
    }

    /// Payload room left in the open volume once `ahead` more bytes are in it.
    fn room_after(&self, ahead: u64) -> u64 {
        let used = self.open.as_ref().map_or(0, |volume| volume.used);
        self.volume_size
            .saturating_sub(used + self.tail_len + ahead)
    }

    /// Header length depends only on the member, not on the fragment.
    fn header_len(&self, head: &FragmentHead<'_>, packed_len: u64) -> Result<u64> {
        let probe = packed_len.min(self.volume_size);
        Ok(head.header(false, true, probe, 0, self.header_key)?.len() as u64)
    }

    /// `reserve` is the room to leave after the member's last byte, or it goes on into the next volume.
    fn write_member(&mut self, mut member: VolumeMember<'_>, reserve: u64) -> Result<()> {
        let name = member.head.name;
        self.write_fragments(&mut member, reserve).map_err(|error| {
            crate::write_stream::member_error(error, name, "writing volume member")
        })
    }

    fn write_fragments(&mut self, member: &mut VolumeMember<'_>, reserve: u64) -> Result<()> {
        let header_len = self.header_len(&member.head, member.packed_len)?;
        let mut start = 0;
        // A fragment can be empty, so `start` alone doesn't say whether one came before.
        let mut continued = false;
        loop {
            crate::write_progress::check_cancelled(Some(self.progress))?;
            if self.open.is_none() {
                self.start_volume()?;
            }
            let volume = self.open.as_ref().expect("volume started");
            let room = self
                .volume_size
                .saturating_sub(volume.used)
                .saturating_sub(self.tail_len)
                .saturating_sub(header_len);
            let remaining = member.packed_len - start;
            // A member with no data still needs room for its header.
            let header_fits = volume.used + self.tail_len + header_len <= self.volume_size;
            if !header_fits || (room == 0 && remaining > 0) {
                if volume.fragments == 0 {
                    return Err(Error::InvalidArgument(
                        "volume size is too small to hold the volume headers",
                    ));
                }
                // Readers would stop at this volume: see `boundary_reserves`.
                if volume.ends_member && !writes_end_block(self.target) {
                    return Err(Error::InvalidArgument(
                        "volume size is too small to hold the end of one member and the start of the next",
                    ));
                }
                self.close_volume(true)?;
                continue;
            }
            let mut len = remaining.min(room);
            if len == remaining && remaining > 0 && room - remaining < reserve {
                if remaining == 1 && volume.fragments == 0 {
                    // A fresh volume would do the same again.
                    return Err(Error::InvalidArgument(
                        "volume size is too small to hold the end of one member and the start of the next",
                    ));
                }
                len = remaining - 1;
            }
            let split_after = start + len < member.packed_len;
            // The header carries the CRC of what follows it, so it goes out as
            // a placeholder and is patched once the payload has been copied.
            let volume = self.open.as_mut().expect("volume started");
            volume.out.write_all(&vec![0; header_len as usize])?;
            let fragment_crc = member.payload.copy(len, &mut *volume.out)?;
            let file_crc = match (split_after, member.final_crc) {
                (true, _) => fragment_crc,
                (false, Some(crc)) => crc,
                (false, None) => member.payload.unpacked_crc(),
            };
            self.close_fragment(
                &member.head,
                Fragment {
                    header_len,
                    continued,
                    split_after,
                    len,
                    crc: fragment_crc,
                },
                file_crc,
            )?;
            start += len;
            continued = true;
            if !split_after {
                return Ok(());
            }
            self.close_volume(true)?;
        }
    }

    /// Patches the header of the fragment just written behind it and counts it into the volume.
    fn close_fragment(
        &mut self,
        head: &FragmentHead<'_>,
        fragment: Fragment,
        file_crc: u32,
    ) -> Result<()> {
        let Fragment {
            header_len,
            continued,
            split_after,
            len,
            crc,
        } = fragment;
        let header = head.header(continued, split_after, len, file_crc, self.header_key)?;
        if header.len() as u64 != header_len {
            return Err(Error::WriterFailure(
                "legacy file header changed length when patched",
            ));
        }
        let volume = self.open.as_mut().expect("volume started");
        let back = i64::try_from(header_len + len)
            .map_err(|_| Error::InvalidArgument("legacy volume fragment is too long"))?;
        volume.out.seek(SeekFrom::Current(-back))?;
        volume.out.write_all(&header)?;
        volume
            .out
            .seek(SeekFrom::Current(back - header_len as i64))?;
        volume.crc = crc32_combine(volume.crc, crc32(&header), header_len);
        volume.crc = crc32_combine(volume.crc, crc, len);
        volume.used += header_len + len;
        volume.fragments += 1;
        volume.ends_member = !split_after;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        if self.open.is_some() {
            self.close_volume(false)?;
        }
        Ok(())
    }

    fn head(&self, index: u64) -> Result<Vec<u8>> {
        let mut main_flags = MHD_VOLUME | self.main_flags;
        if self.header_key.is_some() {
            main_flags |= MHD_PASSWORD;
        }
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }
        let mut head = Vec::new();
        head.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut head, main_flags);
        // Later volumes carry it in their tail instead: see `tail`.
        if index == 0 {
            write_lead(
                &mut head,
                self.target,
                &self.comment,
                self.header_key,
                Some(self.progress),
            )?;
        }
        Ok(head)
    }

    fn start_volume(&mut self) -> Result<()> {
        self.tail_len = self.tail(self.index, false, 0)?.len() as u64;
        let head = self.head(self.index)?;
        let mut out = self.sink.start_volume(self.index)?;
        out.write_all(&head)?;
        self.open = Some(OpenVolume {
            out,
            used: head.len() as u64,
            fragments: 0,
            ends_member: false,
            crc: crc32(&head),
        });
        Ok(())
    }

    fn close_volume(&mut self, more: bool) -> Result<()> {
        let mut volume = self.open.take().expect("volume open");
        let tail = self.tail(self.index, more, volume.crc)?;
        let len = volume.used + tail.len() as u64;
        if len > self.volume_size {
            return Err(Error::WriterFailure(
                "legacy volume came out longer than the volume size",
            ));
        }
        volume.out.write_all(&tail)?;
        volume.out.flush()?;
        drop(volume.out);
        self.sink.finish_volume(self.index, len)?;
        self.progress.report(WriteProgressEvent::VolumeFinished {
            volume_index: self.index as usize,
            total_volumes: if more {
                self.total_volumes
            } else {
                Some(self.index as usize + 1)
            },
            bytes: len,
        });
        self.index += 1;
        crate::write_progress::check_cancelled(Some(self.progress))
    }

    /// A later volume's producer record goes after its files, so a split
    /// member's header comes first, as RAR writes it and python-rarfile reads it.
    /// `data_crc` covers the volume up to the tail; the end block's CRC takes in the producer record too.
    fn tail(&self, index: u64, more: bool, data_crc: u32) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if index > 0 {
            write_producer(&mut out, self.target, self.header_key, Some(self.progress))?;
        }
        let data_crc = crc32_combine(data_crc, crc32(&out), out.len() as u64);
        match self.header_key {
            Some(key) => {
                write_encrypted_end_block(&mut out, &volume_end_block(index, more, data_crc), key)?
            }
            None if writes_end_block(self.target) => {
                out.extend_from_slice(&volume_end_block(index, more, data_crc))
            }
            None => {}
        }
        Ok(out)
    }
}

/// Room kept past a streamed block for cipher bytes held from the last one and the final padding.
const SEAL_MARGIN: u64 = 32;

/// Codes a member into the set as it reads; volumes are handed on as they fill.
#[allow(clippy::too_many_arguments)]
fn stream_member_into(
    packer: &mut VolumePacker<'_>,
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    data_keys: &mut DataKeys,
    solid: Option<SolidLink<'_>>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
) -> Result<u8> {
    let mut out = StreamedFragments {
        head: FragmentHead {
            name: member.name,
            target: options.target,
            unpacked_size: member.unpacked_size()?,
            file_time: member.file_time,
            file_attr: member.file_attr,
            host_os: member.host_os,
            method: 0x30,
            dictionary_flags: dictionary_flags_for_options(options)?,
            file_flags: 0,
            salt: None,
        },
        packer,
        password: member.password,
        continues: solid.as_ref().is_some_and(|link| link.continues),
        header_len: 0,
        continued: false,
        len: 0,
        crc: Crc32::new(),
        first_at: None,
        committed: false,
        held: Vec::new(),
    };
    stream_member(
        &mut out, member, options, coding, data_keys, solid, resources, progress,
    )
}

/// Rewinding for a stored copy only works in the open volume, so a member commits when its first one fills.
struct StreamedFragments<'p, 'a, 'm> {
    packer: &'p mut VolumePacker<'a>,
    head: FragmentHead<'m>,
    password: Option<&'m [u8]>,
    continues: bool,
    header_len: u64,
    /// The open fragment follows one in an earlier volume.
    continued: bool,
    len: u64,
    crc: Crc32,
    /// Where the payload starts, while the member is still in its first volume.
    first_at: Option<u64>,
    committed: bool,
    /// Opening bytes that did not fit before anything was coded to judge the member by.
    held: Vec<u8>,
}

impl StreamedFragments<'_, '_, '_> {
    fn set_method(&mut self, method: u8) {
        self.head.method = method;
        let continuation = self.continues && method != 0x30;
        self.head.file_flags = writer_file_flags(self.password, None, continuation)
            | if self.head.salt.is_some() {
                FHD_SALT
            } else {
                0
            };
    }

    fn room(&self) -> u64 {
        self.packer.room_after(self.header_len + self.len)
    }

    /// Writes a placeholder header where payload fits after it, in a fresh volume if this one is full.
    fn open_fragment(&mut self) -> Result<()> {
        loop {
            crate::write_progress::check_cancelled(Some(self.packer.progress))?;
            if self.packer.open.is_none() {
                self.packer.start_volume()?;
            }
            if self.packer.room_after(self.header_len) > 0 {
                break;
            }
            if self.packer.open.as_ref().expect("volume started").fragments == 0 {
                return Err(Error::InvalidArgument(
                    "volume size is too small to hold the volume headers",
                ));
            }
            self.packer.close_volume(true)?;
        }
        let volume = self.packer.open.as_mut().expect("volume started");
        volume.out.write_all(&vec![0; self.header_len as usize])?;
        if !self.continued {
            self.first_at = Some(volume.used + self.header_len);
        }
        self.len = 0;
        self.crc = Crc32::new();
        Ok(())
    }

    fn fragment(&self, split_after: bool) -> Fragment {
        Fragment {
            header_len: self.header_len,
            continued: self.continued,
            split_after,
            len: self.len,
            crc: self.crc.finish(),
        }
    }
}

impl StreamedOut for StreamedFragments<'_, '_, '_> {
    fn begin(&mut self, salt: Option<[u8; 8]>, sizes: HeaderPayload) -> Result<()> {
        self.head.salt = salt;
        self.set_method(sizes.method);
        self.header_len = self.packer.header_len(&self.head, sizes.unpacked_size)?;
        self.open_fragment()
    }

    fn goes_on(&mut self, packed: u64, block: u64, coded: u64, unpacked: u64) -> bool {
        if self.committed {
            return true;
        }
        if packed + block >= unpacked {
            return false;
        }
        // A PPMd member's opening bytes code nothing yet, so they wait in `held` for evidence.
        if coded == 0 || self.held.len() as u64 + block + SEAL_MARGIN <= self.room() {
            return true;
        }
        self.committed = packed + block < coded;
        self.committed
    }

    fn write_packed(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.committed && (!self.held.is_empty() || self.room() < bytes.len() as u64) {
            self.held.extend_from_slice(bytes);
            return Ok(());
        }
        let held = std::mem::take(&mut self.held);
        self.write_through(&held)?;
        self.write_through(bytes)
    }

    fn restart(&mut self) -> Result<()> {
        let at = self.first_at.ok_or(Error::WriterFailure(
            "streamed volume member restarted after its first volume closed",
        ))?;
        let volume = self.packer.open.as_mut().expect("fragment open");
        volume.out.seek(SeekFrom::Start(at))?;
        self.len = 0;
        self.crc = Crc32::new();
        self.held.clear();
        self.committed = true;
        self.set_method(0x30);
        Ok(())
    }

    fn finish(&mut self, sizes: HeaderPayload) -> Result<()> {
        // A member that ends uncommitted has packed smaller than it is, so it keeps what it holds.
        self.committed = true;
        let held = std::mem::take(&mut self.held);
        self.write_through(&held)?;
        self.set_method(sizes.method);
        let fragment = self.fragment(false);
        self.packer
            .close_fragment(&self.head, fragment, sizes.file_crc)
    }
}

impl StreamedFragments<'_, '_, '_> {
    /// Writes committed bytes, closing each volume as it fills.
    fn write_through(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let room = self.room();
            if room == 0 {
                if !self.committed {
                    return Err(Error::WriterFailure(
                        "streamed volume member split before it committed",
                    ));
                }
                let fragment = self.fragment(true);
                let crc = fragment.crc;
                self.packer.close_fragment(&self.head, fragment, crc)?;
                self.packer.close_volume(true)?;
                self.continued = true;
                self.first_at = None;
                self.open_fragment()?;
                continue;
            }
            let take = room.min(bytes.len() as u64) as usize;
            let volume = self.packer.open.as_mut().expect("fragment open");
            volume.out.write_all(&bytes[..take])?;
            self.crc.update(&bytes[..take]);
            self.len += take as u64;
            bytes = &bytes[take..];
        }
        Ok(())
    }
}

/// Fixed once so both reads of the source produce the same ciphertext.
pub(super) struct CipherPlan<'a> {
    target: ArchiveVersion,
    password: Option<&'a [u8]>,
    #[cfg(feature = "encryption")]
    rar30: Option<([u8; 8], Rar30Cipher)>,
}

impl<'a> CipherPlan<'a> {
    pub(super) fn new(
        target: ArchiveVersion,
        password: Option<&'a [u8]>,
        data_keys: &mut DataKeys,
    ) -> Result<Self> {
        #[cfg(not(feature = "encryption"))]
        {
            let _ = data_keys;
            match password {
                None => Ok(Self { target, password }),
                Some(_) => Err(Error::FeatureDisabled {
                    feature: "encryption",
                }),
            }
        }
        #[cfg(feature = "encryption")]
        {
            let rar30 = match (password, target) {
                (None, _) | (Some(_), ArchiveVersion::Rar15 | ArchiveVersion::Rar20) => None,
                (
                    Some(secret),
                    ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40,
                ) => Some(data_keys.rar30(secret)?),
                _ => return Err(Error::UnsupportedVersion(target)),
            };
            Ok(Self {
                target,
                password,
                rar30,
            })
        }
    }

    pub(super) fn salt(&self) -> Option<[u8; 8]> {
        #[cfg(feature = "encryption")]
        {
            self.rar30.as_ref().map(|(salt, _)| *salt)
        }
        #[cfg(not(feature = "encryption"))]
        None
    }

    /// RAR 2.0 onwards encrypts in 16-byte blocks and pads the last one.
    fn pads(&self) -> bool {
        self.password.is_some() && self.target != ArchiveVersion::Rar15
    }

    pub(super) fn packed_len(&self, unpacked: u64) -> Result<u64> {
        if self.pads() {
            unpacked
                .checked_add(15)
                .map(|len| len & !15)
                .ok_or(Error::InvalidArgument("RAR 1.5 block size overflows"))
        } else {
            Ok(unpacked)
        }
    }

    pub(super) fn start(&self) -> Result<Option<Cipher>> {
        let Some(password) = self.password else {
            return Ok(None);
        };
        #[cfg(not(feature = "encryption"))]
        {
            let _ = password;
            Err(Error::FeatureDisabled {
                feature: "encryption",
            })
        }
        #[cfg(feature = "encryption")]
        {
            Ok(Some(match (&self.rar30, self.target) {
                (Some((_, cipher)), _) => Cipher::Rar30(Box::new(cipher.clone())),
                (None, ArchiveVersion::Rar15) => Cipher::Rar15(Rar15Cipher::new(password)),
                (None, _) => Cipher::Rar20(Box::new(Rar20Cipher::new(password))),
            }))
        }
    }
}

pub(super) enum Cipher {
    #[cfg(feature = "encryption")]
    Rar15(Rar15Cipher),
    #[cfg(feature = "encryption")]
    Rar20(Box<Rar20Cipher>),
    #[cfg(feature = "encryption")]
    Rar30(Box<Rar30Cipher>),
}

impl Cipher {
    pub(super) fn encrypt(&mut self, data: &mut [u8]) {
        match self {
            #[cfg(feature = "encryption")]
            Self::Rar15(cipher) => cipher.crypt_in_place(data),
            #[cfg(feature = "encryption")]
            Self::Rar20(cipher) => cipher
                .encrypt_in_place(data)
                .expect("stream chunks are block aligned"),
            #[cfg(feature = "encryption")]
            Self::Rar30(cipher) => cipher
                .encrypt_in_place(data)
                .expect("stream chunks are block aligned"),
            #[cfg(not(feature = "encryption"))]
            _ => {
                let _ = data;
                unreachable!("no cipher without the encryption feature")
            }
        }
    }
}

/// The member as stored: read in pieces, encrypted and padded if asked.
struct PackedStream<'a> {
    reader: Box<dyn Read + 'a>,
    expected: u64,
    left: u64,
    cipher: Option<Cipher>,
    pads: bool,
    buffer: Vec<u8>,
    position: usize,
    unpacked_crc: Crc32,
    progress: ProgressReporter<'a>,
    work: Option<&'a WorkTracker<'a>>,
}

impl<'a> PackedStream<'a> {
    fn open(
        bytes: &MemberBytes<'a>,
        expected: u64,
        cipher: &CipherPlan<'_>,
        progress: ProgressReporter<'a>,
        work: Option<&'a WorkTracker<'a>>,
    ) -> Result<Self> {
        Ok(Self {
            reader: bytes.open()?,
            expected,
            left: expected,
            cipher: cipher.start()?,
            pads: cipher.pads(),
            buffer: Vec::with_capacity(STREAM_CHUNK + 16),
            position: 0,
            unpacked_crc: Crc32::new(),
            progress,
            work,
        })
    }

    fn unpacked_crc(&self) -> u32 {
        self.unpacked_crc.finish()
    }

    /// Copies the next `len` packed bytes to `out`, returning their CRC.
    fn copy(&mut self, mut len: u64, out: &mut dyn Write) -> Result<u32> {
        let mut crc = Crc32::new();
        while len > 0 {
            if self.position == self.buffer.len() {
                self.fill()?;
            }
            let take = len.min((self.buffer.len() - self.position) as u64) as usize;
            let bytes = &self.buffer[self.position..self.position + take];
            crc.update(bytes);
            out.write_all(bytes)?;
            self.position += take;
            len -= take as u64;
        }
        Ok(crc.finish())
    }

    fn fill(&mut self) -> Result<()> {
        const CHANGED: &str = "entry source size changed while writing";
        crate::write_progress::check_cancelled(Some(self.progress))?;
        if self.left == 0 {
            return Err(Error::WriterFailure(
                "legacy volume payload ran past the member",
            ));
        }
        let want = self.left.min(STREAM_CHUNK as u64) as usize;
        self.buffer.clear();
        self.buffer.resize(want, 0);
        self.reader
            .read_exact(&mut self.buffer)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::SourceChanged(CHANGED),
                _ => error.into(),
            })?;
        self.left -= want as u64;
        self.unpacked_crc.update(&self.buffer);
        if let Some(work) = self.work {
            work.advance(want as u64);
        }
        if self.left == 0 {
            crate::write_stream::check_source_length(
                &mut self.reader,
                self.expected,
                self.expected,
                CHANGED,
            )?;
            if self.pads {
                self.buffer.resize(want.next_multiple_of(16), 0);
            }
        }
        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(&mut self.buffer);
        }
        self.position = 0;
        Ok(())
    }
}
