use super::*;
use crate::codec::rar13::{
    unpack15_encode_with_options_and_progress, EncodeOptions as Rar15EncodeOptions, Unpack15Encoder,
};
use crate::codec::rar20::{
    unpack20_encode_auto_with_options_and_progress, EncodeOptions as Rar20EncodeOptions,
    Unpack20Encoder,
};
use crate::codec::rar29::{
    unpack29_encode_literals, unpack29_encode_literals_with_options,
    unpack29_encode_literals_with_options_and_progress, unpack29_encode_ppmd,
    unpack29_encode_ppmd_with_filter, EncodeOptions as Rar29EncodeOptions, Unpack29Encoder,
};
use crate::crc32::Crc32;
pub use crate::filter::{FilterKind, FilterPolicy, FilterSpec};
use crate::io_util::align16 as checked_align16;
use crate::streaming::WriterResources;
use crate::write_plan::{MemberCoding, PlanShape, WriterOption};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::write_stream::{MemberBytes, MemberPayload};
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::io::Write;

const AUTO_RGB_WIDTHS: [usize; 4] = [24, 48, 96, 192];
const MIN_STORE_FALLBACK_SIZE: usize = 1024;
const RAR29_TEXT_SAMPLE_SIZE: usize = 8192;

/// How long a run of NUL has to be before the text screen reads it as padding
/// and stops counting it either way.
///
/// Sixteen is well past what falls out of text (a run of NUL in a source file
/// is already unusual) and well short of the 512 byte blocks tar pads to.
/// Measured across 400 binaries over 200 KB in `/usr/bin` and
/// `/usr/lib/x86_64-linux-gnu`, 8, 16 and 32 all give the same answer, so the
/// exact number is not load-bearing.
const RAR29_NUL_RUN_IS_PADDING: usize = 16;

/// The level an absent `--level` means for RAR 2.0, matching the method byte
/// `compression_method_for_level` writes for it.
const RAR20_DEFAULT_LEVEL: u8 = 3;
const RAR29_AUDIO_SAMPLE_SIZE: usize = 8192;
/// How much data one RAR 2.9 LZ block covers.
///
/// Every block carries its own Huffman tables, so this is the distance over
/// which the tables have to fit the data. A megabyte was far too long a lease:
/// a binary's code and its data want different tables, and one set fitted to
/// both is worse than either. Measured on `--level 5`, packed bytes:
///
/// ```text
/// block         16K      32K      64K     128K       1M
/// libc       686400   683942   684278   704689   797692
/// python     632452   628926   627862   648835   738624
/// mixed      136376   135530   135264   146831   149372
/// lorem       16186    16186    16186    16186    16186
/// ```
///
/// 64K is the best or within a rounding error of it on everything measured,
/// and text does not care either way. The curve turns back up below 32K, where
/// re-sending the tables starts to cost more than fitting them gains.
const RAR29_LZ_BLOCK_SIZE: usize = 64 * 1024;

/// The largest dictionary the format encodes, used when a memory estimate
/// cannot resolve the real one. It has to stay an upper bound, so it does not
/// follow the block size.
const RAR29_MAX_DICTIONARY_SIZE: usize = 4 * 1024 * 1024;
const RAR15_ALIGN_OVERFLOW: &str = "RAR 1.5 block size overflows usize";

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_stored).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Stored,
        archive_comment,
        None,
    )
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive_with_comment(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment_and_progress(entries, options, archive_comment, None)
}

pub fn write_compressed_archive_with_comment_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_file).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Compressed,
        archive_comment,
        progress,
    )
}

pub fn write_rar29_compressed_archive_with_filter_policy(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>> {
    write_rar29_compressed_archive_with_filter_policy_and_progress(entries, options, policy, None)
}

pub fn write_rar29_compressed_archive_with_filter_policy_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_file).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Filtered(policy),
        None,
        progress,
    )
}

/// Writes an archive straight to `output`, holding only the members being
/// compressed rather than every input at once.
///
/// `resources` bounds how many members are in flight, which is what keeps the
/// peak flat across an archive of many files. One member still has to fit:
/// these codecs compress a member as a unit, so a member larger than the budget
/// is compressed on its own rather than refused.
pub fn write_streaming_archive_to(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn Write,
) -> Result<()> {
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        output,
    )
}

/// Runs the streaming writer into a buffer, for the callers that want the
/// archive as bytes. The budget still applies, so a many-file archive holds one
/// window of members rather than all of them.
fn collect_archive(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_archive_to(
        members,
        options,
        coding,
        archive_comment,
        &WriterResources::default(),
        progress,
        &mut out,
    )?;
    Ok(out)
}

fn write_archive_to(
    members: &[Member<'_>],
    mut options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn Write,
) -> Result<()> {
    let has_file_comment = members.iter().any(|member| member.file_comment.is_some());
    validate_plan(
        options,
        coding.shape(),
        archive_comment.is_some(),
        has_file_comment,
    )?;
    if let MemberCoding::Filtered(policy) = &coding {
        validate_rar29_filter_policy(policy, options.method, options.features.solid)?;
    }
    let header_password = if options.features.header_encryption {
        validate_header_encrypted_archive_options(
            options.target,
            archive_comment.is_some(),
            members.iter().any(|member| member.password.is_some()),
        )?;
        Some(header_encryption_password(
            members.iter().map(|member| member.password),
        )?)
    } else {
        None
    };

    let mut total_bytes = 0u64;
    let mut largest_member = 0u64;
    for member in members {
        let unpacked = member.unpacked_size()? as u64;
        total_bytes = total_bytes.saturating_add(unpacked);
        largest_member = largest_member.max(unpacked);
    }
    if options.dictionary_size.is_none() {
        // A solid run is one stream, so its window has to reach back across the
        // members it already coded; independent members only ever look inside
        // themselves.
        let reach = if options.features.solid && coding.compresses() {
            total_bytes
        } else {
            largest_member
        };
        options.dictionary_size = Some(fitted_dictionary_size(options.target, reach));
    }
    // RAR 2.0 walks a non-solid member twice, once to pick a method and once to
    // encode it, so its progress total counts every byte twice.
    let total_work = if options.target == ArchiveVersion::Rar20
        && !options.features.solid
        && coding.compresses()
    {
        total_bytes.saturating_mul(2)
    } else {
        total_bytes
    };
    let reporting = coding.compresses().then_some(progress).flatten();
    report_compression_operation(reporting, true, total_work, members.len());
    let work = WorkTracker::new(
        reporting.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );

    let result = write_members_to(
        members,
        options,
        &coding,
        archive_comment,
        header_password,
        resources,
        Some(&work),
        output,
    );
    if result.is_ok() && !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(reporting, false, total_work, members.len());
    result
}

#[allow(clippy::too_many_arguments)]
fn write_members_to(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: &MemberCoding,
    archive_comment: Option<&[u8]>,
    header_password: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&WorkTracker<'_>>,
    output: &mut dyn Write,
) -> Result<()> {
    output.write_all(RAR15_SIGNATURE)?;
    let mut main_flags = 0;
    if options.features.solid && coding.compresses() {
        main_flags |= MHD_SOLID;
    }
    if header_password.is_some() {
        main_flags |= MHD_PASSWORD;
    }
    if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
        main_flags |= MHD_COMMENT;
    }
    let mut head = Vec::new();
    write_main_header(&mut head, main_flags);
    write_archive_comment(&mut head, archive_comment, options.target)?;
    output.write_all(&head)?;

    // Solid members share one encoder, so they are coded in order. Independent
    // ones are coded a window at a time and written as each window lands.
    if options.features.solid && coding.compresses() {
        let mut solid_encoder = SolidEncoder::for_target(options, true)?;
        let mut solid_run_has_member = false;
        for member in members {
            let encoded = encode_member(
                member,
                options,
                coding,
                &mut solid_encoder,
                resources,
                progress,
            )?;
            let solid_continuation = encoded.method != 0x30 && solid_run_has_member;
            // Storing a member rebuilds the encoder, so the chain ends there.
            // An empty compressed member leaves the chain exactly as it was:
            // it feeds the encoder nothing, and readers pass over an empty
            // payload without advancing their decoder. Counting one as a
            // member left the next one flagged as continuing a chain that had
            // been broken by a stored member two places back.
            if encoded.method == 0x30 {
                solid_run_has_member = false;
            } else if encoded.unpacked_size != 0 {
                solid_run_has_member = true;
            }
            write_member(
                output,
                member,
                encoded,
                options,
                solid_continuation,
                header_password,
            )?;
        }
    } else {
        crate::parallel::map_slice_windowed(
            members,
            crate::parallel::default_window(),
            |member| encode_member(member, options, coding, &mut None, resources, progress),
            |member, encoded| {
                write_member(output, member, encoded, options, false, header_password)
            },
        )?;
    }
    if let Some(password) = header_password {
        write_encrypted_end_block(output, password)?;
    }
    Ok(())
}

/// Encodes one member, choosing an engine and a filter independently.
///
/// The two are separate questions: which engine compresses this content best,
/// and which transform makes it easier to compress. They used to be one enum,
/// which meant some combinations simply could not be asked for.
fn encode_rar29_policy_filtered_payload(
    data: &[u8],
    policy: &FilterPolicy,
    method: Rar29Method,
    options: Rar29EncodeOptions,
    lz_method: u8,
    ppmd_trial: bool,
) -> Result<EncodedPayload> {
    // An empty member is stored whatever was asked for. A filter over it is a
    // 0..0 range, which the codec refuses, so an archive holding one empty file
    // used to compress every other member and then fail at the last step. Only
    // the search path guarded this; every explicit policy walked into it.
    if lz_method == 0x30 || data.is_empty() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    // The method byte carries the level that was asked for, not which engine
    // answered. RAR 2.9 signals PPMd inside the stream (our own decoder takes
    // no method byte at all), and WinRAR 3.00 stamps 0x34 on the PPMd archive
    // it writes at -m4. Stamping 0x35 on every PPMd payload only looked right
    // while the trial ran at level 5, and made a level 3 archive claim to be a
    // level 5 one as soon as it ran anywhere else.
    let ppmd = |data: &[u8]| -> Result<EncodedPayload> {
        Ok(EncodedPayload {
            data: unpack29_encode_ppmd(data, options.max_match_distance).map_err(Error::from)?,
            method: lz_method,
        })
    };
    match (method, policy) {
        (Rar29Method::Ppmd, FilterPolicy::None) => ppmd(data),
        (Rar29Method::Ppmd, FilterPolicy::Explicit(filter)) => Ok(EncodedPayload {
            data: unpack29_encode_ppmd_with_filter(
                data,
                filter.clone(),
                options.max_match_distance,
            )
            .map_err(Error::from)?,
            method: lz_method,
        }),
        // Rejected by validate_rar29_filter_policy before any encoding starts.
        (Rar29Method::Ppmd, FilterPolicy::Auto) => Err(Error::InvalidHeader(
            "RAR 2.9 cannot search for a filter while PPMd is forced",
        )),
        (Rar29Method::Lz, FilterPolicy::None) => encode_rar29_lz_member(data, options, lz_method),
        (Rar29Method::Lz, FilterPolicy::Auto) => {
            encode_rar29_auto_filtered_member(data, options, lz_method, false)
        }
        (Rar29Method::Lz, FilterPolicy::Explicit(filter)) => Ok(EncodedPayload {
            data: encode_rar29_filtered_member(data, filter.clone(), options)?,
            method: lz_method,
        }),
        (Rar29Method::Auto, FilterPolicy::Auto) => {
            encode_rar29_auto_filtered_member(data, options, lz_method, ppmd_trial)
        }
        (Rar29Method::Auto, policy) => {
            let mut best = match policy {
                FilterPolicy::Explicit(filter) => EncodedPayload {
                    data: encode_rar29_filtered_member(data, filter.clone(), options)?,
                    method: lz_method,
                },
                _ => encode_rar29_lz_member(data, options, lz_method)?,
            };
            // Gated on the content, so a binary member never pays for a PPMd
            // encode it was always going to lose.
            if ppmd_trial && is_text_ppmd_candidate(data) {
                let candidate = ppmd(data)?;
                if candidate.data.len() < best.data.len() {
                    best = candidate;
                }
            }
            Ok(best)
        }
    }
}

/// Whether this level is willing to encode the member twice to choose an engine.
///
/// Takes the resolved level, not the option. Reading `Option<u8>` meant an
/// absent level and `--level 3` disagreed, though both write method 0x33: the
/// default paid for the trial and the level that names the same number did not,
/// so the two produced archives 24% apart on the same 4 MiB of text.
///
/// Levels 1 and 2 are the ones asking for speed and still skip it. Level 3 is
/// the default and where most archives are written, and it is worth about a
/// fifth of the size on text for roughly twice the encode. WinRAR turns PPMd on
/// one level later, at m4: on the bench text member WinRAR 3.00 packs 657,294
/// bytes at m3 and 585,357 at m4, where we now write 540,517 at both.
fn ppmd_trial_pays(level: u8) -> bool {
    level >= 3
}

fn validate_rar29_filter_policy(
    policy: &FilterPolicy,
    method: Rar29Method,
    solid: bool,
) -> Result<()> {
    // Searching for a filter means measuring candidates against each other,
    // and the search only knows how to measure them through LZ.
    if matches!(policy, FilterPolicy::Auto) && method == Rar29Method::Ppmd {
        return Err(Error::InvalidHeader(
            "RAR 2.9 cannot search for a filter while PPMd is forced",
        ));
    }
    // Every candidate would have to be measured against the history so far,
    // which means encoding each one against the live chain. Naming the filter
    // costs nothing extra and is what the search would settle on anyway.
    if matches!(policy, FilterPolicy::Auto) && solid {
        return Err(Error::InvalidHeader(
            "RAR 2.9 cannot search for a filter in a solid archive; name one instead",
        ));
    }
    let filter = match policy {
        FilterPolicy::Explicit(filter) => filter,
        FilterPolicy::None | FilterPolicy::Auto => return Ok(()),
    };
    match filter.kind {
        FilterKind::Delta { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 DELTA filter channel count is invalid",
                ));
            }
        }
        FilterKind::Audio { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 AUDIO filter channel count is invalid",
                ));
            }
        }
        FilterKind::Rgb { width, pos_r } => {
            if width == 0 || !width.is_multiple_of(3) || pos_r > 2 {
                return Err(Error::InvalidHeader(
                    "RAR 2.9 RGB filter parameters are invalid",
                ));
            }
        }
        FilterKind::E8 | FilterKind::E8E9 | FilterKind::Itanium => {}
        // Refused here rather than in the codec, so nothing is compressed
        // before the caller is told the filter cannot be written.
        FilterKind::Arm => {
            return Err(Error::InvalidHeader(
                "the ARM filter is only available for RAR 5 and RAR 7 writers",
            ))
        }
    }
    Ok(())
}

fn encode_rar29_lz_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    method: u8,
) -> Result<EncodedPayload> {
    let compressed = unpack29_encode_literals_with_options(data, options).map_err(Error::from)?;
    if compressed.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: compressed,
        method,
    })
}

fn encode_rar29_filtered_member(
    data: &[u8],
    filter: FilterSpec,
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filter(data, filter)
        .map_err(Error::from)
}

fn encode_rar29_filtered_members(
    data: &[u8],
    filters: &[FilterSpec],
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filters(data, filters)
        .map_err(Error::from)
}

/// How the RAR 2.9 family measures a filter candidate, for the shared search.
#[derive(Clone, Copy)]
struct Rar29Search;

impl crate::filter_search::FilterSearch for Rar29Search {
    type Options = Rar29EncodeOptions;

    fn screened_kinds(&self, data: &[u8]) -> Vec<FilterKind> {
        let mut kinds = vec![FilterKind::Itanium];
        for channels in 1..=4 {
            kinds.push(FilterKind::Delta { channels });
            // Free to ask, and it keeps the screened set from doubling.
            if is_audio_filter_candidate(data, channels) {
                kinds.push(FilterKind::Audio { channels });
            }
        }
        kinds.extend(
            AUTO_RGB_WIDTHS
                .into_iter()
                .filter(|&width| data.len() >= width)
                .map(|width| FilterKind::Rgb { width, pos_r: 0 }),
        );
        kinds
    }

    /// Unlike RAR 5, a greedy parse here really is cheaper. On a megabyte of
    /// binary it measured 59ms against 91ms at full effort, and it ranks
    /// candidates the same way, so the screens run reduced and only the
    /// finalists pay full price.
    fn screen_options(&self, options: Rar29EncodeOptions) -> Rar29EncodeOptions {
        let mut ranking = Rar29EncodeOptions::new(options.max_match_candidates.min(8))
            .with_lazy_matching(false)
            .with_max_match_distance(options.max_match_distance);
        if let Some(block_size) = options.block_size {
            ranking = ranking.with_block_size(block_size);
        }
        ranking
    }

    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>> {
        crate::codec::rar29::filtered_members(data, filters)
            .map(|filtered| filtered.data)
            .map_err(Error::from)
    }

    fn encode_plain(
        &self,
        data: &[u8],
        options: Rar29EncodeOptions,
        _progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        unpack29_encode_literals_with_options(data, options).map_err(Error::from)
    }

    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Rar29EncodeOptions,
        _progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        encode_rar29_filtered_members(data, filters, options)
    }
}

fn encode_rar29_auto_filtered_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    lz_method: u8,
    include_ppmd: bool,
) -> Result<EncodedPayload> {
    if data.is_empty() {
        return Ok(EncodedPayload {
            data: Vec::new(),
            method: 0x30,
        });
    }
    // The search measures the unfiltered member as one of its own candidates
    // and returns the winner's bytes, so encoding the member plainly here as
    // well was a second full pass over every binary member on the default
    // settings. Text goes nowhere near the search, so it still needs one.
    let text = is_text_ppmd_candidate(data);
    let searching = !text && crate::filter_search::search_applies(data);
    let mut best = EncodedPayload {
        data: if searching {
            crate::filter_search::choose_filter(&Rar29Search, data, options, None)?.1
        } else {
            unpack29_encode_literals_with_options(data, options).map_err(Error::from)?
        },
        method: lz_method,
    };
    // Whichever engine wins, it wins because it was measured against the other
    // over the whole member. Size used to decide it instead: under 1 MiB text
    // was measured, over 16 MiB it went to PPMd unmeasured, and everything
    // between kept the LZ bytes without ever encoding PPMd to compare. That
    // middle band cost 24% on 2 MiB of man pages and 12% on 4 MiB, and the
    // unmeasured end can lose just as badly the other way: 8 MiB of content
    // that repeats every 4 MiB packs to 843 KB under LZ and 1.44 MB under PPMd.
    //
    // Screening on a sample first, the way the filter search earns its
    // candidates, was tried and does not work here. The two engines are only
    // comparable once there is enough output to compare: on 128 KiB of one
    // repeating phrase LZ lands on 213 bytes and PPMd on 118, so the screen
    // reads a 45% PPMd win off what is almost entirely archive overhead. And
    // in the case worth catching, repetition further apart than the sample is
    // wide, the sample cannot see the repetition at all. PPMd costs about
    // three times LZ on the same bytes, so text at the top two levels pays for
    // both engines. Levels 1 to 4 skip the trial as they always have.
    if include_ppmd && text {
        let ppmd = EncodedPayload {
            data: unpack29_encode_ppmd(data, options.max_match_distance).map_err(Error::from)?,
            method: lz_method,
        };
        if ppmd.data.len() < best.data.len() {
            best = ppmd;
        }
    }
    if best.data.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(best)
}

fn is_text_ppmd_candidate(data: &[u8]) -> bool {
    let mut printable = 0usize;
    let mut nul = 0usize;
    let mut total = 0usize;
    for start in text_sample_offsets(data.len()) {
        let end = start.saturating_add(RAR29_TEXT_SAMPLE_SIZE).min(data.len());
        let (window_printable, window_nul, window_total) = score_text_window(&data[start..end]);
        printable += window_printable;
        nul += window_nul;
        total += window_total;
    }
    total != 0 && nul * 100 <= total && printable * 100 >= total * 85
}

/// Counts one sampled window as printable, NUL and total bytes.
///
/// Counting only ASCII read every non-English member as binary. The bench's
/// text member is a set of translated man pages, 23% of it well-formed
/// multibyte UTF-8, and it scored 77% against the 85% bar and went to LZ. A
/// multibyte sequence is as much text as an ASCII letter. Accepting them costs
/// no precision either, because random binary almost never forms one: a lead
/// byte followed by a continuation byte is about 3% of positions, nowhere near
/// enough to carry a binary member over the bar.
fn score_text_window(window: &[u8]) -> (usize, usize, usize) {
    let mut printable = 0usize;
    let mut nul = 0usize;
    let mut total = 0usize;
    let mut index = 0usize;
    while index < window.len() {
        let byte = window[index];
        if byte == 0 {
            let run = window[index..]
                .iter()
                .take_while(|&&byte| byte == 0)
                .count();
            index += run;
            // A run this long is padding rather than content, and padding says
            // nothing about what surrounds it, so it is left out of the count
            // instead of counted against the member. A tar pads every file to a
            // 512 byte block and ends with a block of nothing, which put 27% NUL
            // in front of a 1% bar and sent a tar of source files to LZ as if it
            // were binary. What is left either side of the padding still decides
            // it: a tar of text reads 99.8% text, and an ELF only climbs from
            // 34% to 38%, nowhere near the bar.
            if run < RAR29_NUL_RUN_IS_PADDING {
                nul += run;
                total += run;
            }
        } else if byte.is_ascii_graphic() || matches!(byte, b'\n' | b'\r' | b'\t' | b' ') {
            printable += 1;
            total += 1;
            index += 1;
        } else if let Some(len) = utf8_sequence_len(window, index) {
            printable += len;
            total += len;
            index += len;
        } else if utf8_lead_len(byte).is_some_and(|len| index + len > window.len()) {
            // The window cut a sequence in half. That is an artefact of where
            // the sample lands, not evidence of binary, so the window ends here.
            break;
        } else {
            total += 1;
            index += 1;
        }
    }
    (printable, nul, total)
}

/// How many bytes the sequence starting with this byte claims, if it can start
/// one. Overlong forms (`0xc0`, `0xc1`) and anything past U+10FFFF cannot.
fn utf8_lead_len(byte: u8) -> Option<usize> {
    match byte {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// The length of the well-formed UTF-8 sequence at `index`, if there is one.
fn utf8_sequence_len(window: &[u8], index: usize) -> Option<usize> {
    let len = utf8_lead_len(window[index])?;
    if index + len > window.len() {
        return None;
    }
    window[index + 1..index + len]
        .iter()
        .all(|byte| (0x80..=0xbf).contains(byte))
        .then_some(len)
}

fn text_sample_offsets(len: usize) -> [usize; 3] {
    [
        0,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE) / 2,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE),
    ]
}

fn is_audio_filter_candidate(data: &[u8], channels: usize) -> bool {
    if channels == 0 || channels > 4 || data.len() < channels * 64 {
        return false;
    }

    let mut total_delta = 0usize;
    let mut small_delta = 0usize;
    let mut compared = 0usize;
    for start in text_sample_offsets(data.len()) {
        let end = start
            .saturating_add(RAR29_AUDIO_SAMPLE_SIZE)
            .min(data.len());
        let aligned_start = start + ((channels - start % channels) % channels);
        if aligned_start + channels >= end {
            continue;
        }
        for channel in 0..channels {
            let mut previous = None;
            let mut index = aligned_start + channel;
            while index < end {
                let byte = data[index];
                if let Some(previous) = previous {
                    let delta = usize::from(byte.abs_diff(previous));
                    let delta = delta.min(256 - delta);
                    total_delta += delta;
                    small_delta += usize::from(delta <= 8);
                    compared += 1;
                }
                previous = Some(byte);
                index += channels;
            }
        }
    }

    compared != 0 && total_delta <= compared * 24 && small_delta * 100 >= compared * 55
}

/// One member, however the caller supplied it.
struct Member<'a> {
    name: &'a [u8],
    bytes: MemberBytes<'a>,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    password: Option<&'a [u8]>,
    file_comment: Option<&'a [u8]>,
}

impl<'a> Member<'a> {
    fn from_stored(entry: &'a StoredEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password,
            file_comment: entry.file_comment,
        }
    }

    fn from_file(entry: &'a FileEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password,
            file_comment: entry.file_comment,
        }
    }

    fn from_streaming(entry: &'a StreamingEntry) -> Self {
        Self {
            name: &entry.name,
            bytes: MemberBytes::Source(&entry.source),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password.as_deref(),
            file_comment: entry.file_comment.as_deref(),
        }
    }

    fn unpacked_size(&self) -> Result<usize> {
        usize::try_from(self.bytes.len()?)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 writer does not support large files"))
    }

    /// Checksums a member without holding it, which is how a stored one is
    /// written straight from its source.
    fn checksum(&self) -> Result<u32> {
        let mut crc = Crc32::new();
        self.bytes.walk(|chunk| crc.update(chunk))?;
        Ok(crc.finish())
    }
}

struct EncodedMember<'a> {
    payload: MemberPayload<'a>,
    method: u8,
    unpacked_size: usize,
    file_crc: u32,
}

/// Working memory one member needs while it is coded.
///
/// This is the admission weight that decides how many members run at once, not
/// a prediction: the encoder holds the member, its packed output, and a match
/// finder sized by the block it works in.
fn member_workspace(options: WriterOptions, unpacked: u64, compressing: bool) -> u64 {
    if !compressing {
        return 1024 * 1024;
    }
    let dictionary =
        dictionary_size_for_options(options).unwrap_or(RAR29_MAX_DICTIONARY_SIZE) as u64;
    unpacked
        .saturating_mul(2)
        .saturating_add(dictionary.saturating_mul(12))
        .saturating_add(2 * 1024 * 1024)
}

/// Codes one member, holding its bytes only while it is being coded.
fn encode_member<'a>(
    member: &Member<'a>,
    options: WriterOptions,
    coding: &MemberCoding,
    solid_encoder: &mut Option<SolidEncoder>,
    resources: &WriterResources,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedMember<'a>> {
    let unpacked_size = member.unpacked_size()?;
    validate_member(member.name, unpacked_size)?;
    let _permit = resources.acquire_serialising(member_workspace(
        options,
        unpacked_size as u64,
        coding.compresses(),
    ));

    // A stored member never needs to be resident: checksum it from its source
    // and let the writer copy it straight through.
    if let (MemberCoding::Stored, None, Some(source)) =
        (coding, member.password, member.bytes.source())
    {
        return Ok(EncodedMember {
            payload: MemberPayload::Copied(source),
            method: 0x30,
            unpacked_size,
            file_crc: member.checksum()?,
        });
    }

    let data = member.bytes.load()?;
    let file_crc = crc32(&data);
    let payload = match coding {
        MemberCoding::Stored => EncodedPayload {
            data: data.into_owned(),
            method: 0x30,
        },
        MemberCoding::Compressed => {
            encode_or_store_payload(&data, options, solid_encoder, progress)?
        }
        MemberCoding::Filtered(policy) => {
            encode_filtered_payload(&data, policy, options, solid_encoder)?
        }
    };
    Ok(EncodedMember {
        payload: MemberPayload::Packed(payload.data),
        method: payload.method,
        unpacked_size,
        file_crc,
    })
}

/// Writes one member's header and payload, encrypting either if asked.
fn write_member(
    output: &mut dyn Write,
    member: &Member<'_>,
    encoded: EncodedMember<'_>,
    options: WriterOptions,
    solid_continuation: bool,
    header_password: Option<&[u8]>,
) -> Result<()> {
    let target = options.target;
    validate_writer_password(target, member.password)?;
    let (payload, salt) = match encoded.payload {
        MemberPayload::Packed(mut packed) => {
            let salt = encrypt_packed_data_for_writer(&mut packed, target, member.password)?;
            (MemberPayload::Packed(packed), salt)
        }
        // Unencrypted by construction, so the stored bytes are their own
        // payload and their size is the member's.
        copied => (copied, None),
    };
    let packed_size = payload.size(encoded.unpacked_size as u64);
    let packed_size = usize::try_from(packed_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed size overflows u32"))?;
    let mut flags = writer_file_flags(member.password, member.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let file_comment = encode_file_comment(member.file_comment)?;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: member.name,
            unpacked_size: encoded.unpacked_size,
            file_crc: encoded.file_crc,
            packed_size,
            file_time: member.file_time,
            file_attr: member.file_attr,
            host_os: member.host_os,
            target,
            method: encoded.method,
            dictionary_flags: dictionary_flags_for_options(options)?,
            flags,
            salt,
            extra: &file_comment,
        },
    )?;
    match header_password {
        Some(password) => write_encrypted_header(output, &header, password)?,
        None => output.write_all(&header)?,
    }
    payload.write_to(output, packed_size as u64)
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_plan(options, PlanShape::new().volumes(true), false, false)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: entry.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: 0x30,
            dictionary_flags: dictionary_flags_for_options(options)?,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: 0,
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: entry.data,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: 0x30,
        dictionary_flags: dictionary_flags_for_options(options)?,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: 0,
        password: entry.password,
        max_packed_per_volume,
    })
}

pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volumes_with_progress(entry, options, max_packed_per_volume, None)
}

pub fn write_compressed_volumes_with_progress(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<Vec<u8>>> {
    let total_work = if options.target == ArchiveVersion::Rar20 && !options.features.solid {
        (entry.data.len() as u64).saturating_mul(2)
    } else {
        entry.data.len() as u64
    };
    report_compression_operation(progress, true, total_work, 1);
    let work = WorkTracker::new(
        progress.map(ProgressReporter),
        WriteOperation::Compression,
        total_work,
    );
    let result = write_compressed_volumes_impl(entry, options, max_packed_per_volume, Some(&work));
    if result.is_ok() && !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(progress, false, total_work, 1);
    result
}

fn write_compressed_volumes_impl(
    entry: FileEntry<'_>,
    mut options: WriterOptions,
    max_packed_per_volume: usize,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<Vec<u8>>> {
    validate_plan(
        options,
        PlanShape::new().compressed(true).volumes(true),
        false,
        false,
    )?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;
    // A volume set holds one member, and splitting it changes nothing about
    // how far back the window has to reach.
    if options.dictionary_size.is_none() {
        options.dictionary_size = Some(fitted_dictionary_size(
            options.target,
            entry.data.len() as u64,
        ));
    }

    let mut solid_encoder = None;
    let payload = encode_or_store_payload(entry.data, options, &mut solid_encoder, progress)?;
    if options.features.header_encryption {
        return write_header_encrypted_split_volumes(SplitVolumeRecord {
            name: entry.name,
            unpacked: entry.data,
            packed: &payload.data,
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            target: options.target,
            method: payload.method,
            dictionary_flags: dictionary_flags_for_options(options)?,
            base_flags: writer_file_flags(entry.password, None, false),
            main_flags: if options.features.solid { MHD_SOLID } else { 0 },
            password: entry.password,
            max_packed_per_volume,
        });
    }

    write_split_volumes(SplitVolumeRecord {
        name: entry.name,
        unpacked: entry.data,
        packed: &payload.data,
        file_time: entry.file_time,
        file_attr: entry.file_attr,
        host_os: entry.host_os,
        target: options.target,
        method: payload.method,
        dictionary_flags: dictionary_flags_for_options(options)?,
        base_flags: writer_file_flags(entry.password, None, false),
        main_flags: if options.features.solid { MHD_SOLID } else { 0 },
        password: entry.password,
        max_packed_per_volume,
    })
}

fn report_compression_operation(
    progress: Option<&dyn WriteProgress>,
    started: bool,
    total_bytes: u64,
    total_entries: usize,
) {
    let Some(progress) = progress else { return };
    if started {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    } else {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
}

/// Everything this writer refuses, in one place, before anything is written.
///
/// The three near-identical checks this replaced each built a set of allowed
/// features out of the target and the request together, compared it with the
/// request, and on a mismatch said only that some feature was unsupported.
fn validate_plan(
    options: WriterOptions,
    shape: PlanShape,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    if options.target.family() != crate::version::ArchiveFamily::Rar15To40 {
        return Err(Error::UnsupportedVersion(options.target));
    }
    crate::write_plan::validate_features(options.target, options.features, shape)?;
    crate::write_plan::validate_compression_level(options.target, options.compression_level)?;
    if options.method == Rar29Method::Ppmd {
        crate::write_plan::validate_option(options.target, WriterOption::CompressionMethod, shape)?;
    }
    // A filter policy routes the member through the RAR 2.9 engine, so the
    // formats without one have to be turned away here. This used to be
    // computed into the shape and then never asked about, which let RAR 1.5
    // accept a policy and write an archive that failed its own checksum.
    if shape.filtered {
        crate::write_plan::validate_option(options.target, WriterOption::Filter, shape)?;
    }
    let _ = dictionary_flags_for_options(options)?;
    if has_archive_comment {
        crate::write_plan::validate_option(options.target, WriterOption::ArchiveComment, shape)?;
    }
    if has_file_comment {
        crate::write_plan::validate_option(options.target, WriterOption::FileComment, shape)?;
    }
    Ok(())
}

/// Cross-flag rules: relations between options rather than per-option
/// capability, so they are checked after the capability table has had its say.
fn validate_header_encrypted_archive_options(
    target: ArchiveVersion,
    has_archive_comment: bool,
    has_password: bool,
) -> Result<()> {
    if has_archive_comment {
        return Err(Error::UnsupportedWriterOption {
            target,
            option: WriterOption::ArchiveComment,
            because: Some("with header encryption"),
        });
    }
    if !has_password {
        return Err(Error::UnsupportedWriterOption {
            target,
            option: WriterOption::Feature(crate::Feature::HeaderEncryption),
            because: Some("without a password"),
        });
    }
    Ok(())
}

fn rar29_encode_options_for_level(level: Option<u8>) -> Result<Rar29EncodeOptions> {
    let level = level.unwrap_or(5);
    let candidates = match level {
        0 => 0,
        1 => 8,
        2 => 32,
        3 => 64,
        4 => 96,
        5 => 128,
        _ => {
            return Err(Error::InvalidHeader(
                "RAR compression level must be in the range 0..5",
            ))
        }
    };
    Ok(Rar29EncodeOptions::new(candidates)
        .with_lazy_matching(level >= 4)
        .with_lazy_lookahead(1)
        .with_block_size(RAR29_LZ_BLOCK_SIZE))
}

fn rar29_encode_options_for_options(options: WriterOptions) -> Result<Rar29EncodeOptions> {
    Ok(rar29_encode_options_for_level(options.compression_level)?
        .with_max_match_distance(dictionary_size_for_options(options)?))
}

/// RAR 2.0 levels, as candidates searched per position.
///
/// The ladder used to run 16, 64, 256, 96, 128, so the top two levels searched
/// less than the middle one and asking for more compression got less of it: on
/// 4 MiB of man pages level 3 packed 848,854 bytes, level 5 packed 861,371 and
/// level 4 packed 867,857, which is the candidate order exactly.
///
/// Lazy matching was off at every level, which cost more than the ladder did.
/// Measured on that member, packed bytes and seconds:
///
/// ```text
/// candidates       16       64      256      512     1024
/// lazy off    937,906  878,958  848,790  840,496  835,622
/// lazy on     886,854  837,531  813,252  806,728  803,006
/// seconds        2.37     4.41     8.67    12.78    17.43
/// ```
///
/// It is worth 4% on text and 3% on a stripped binary, at every count, for
/// about half again the time. Candidates cost more and give less: the last
/// doubling buys 0.5%. So lazy matching is on wherever anything is compressed,
/// and the level chooses how far to search.
fn rar20_encode_options_for_level(level: Option<u8>) -> Result<Rar20EncodeOptions> {
    let level = level.unwrap_or(RAR20_DEFAULT_LEVEL);
    let candidates = match level {
        0 => return Ok(Rar20EncodeOptions::new(0)),
        1 => 16,
        2 => 64,
        3 => 256,
        4 => 512,
        5 => 1024,
        _ => {
            return Err(Error::InvalidHeader(
                "RAR compression level must be in the range 0..5",
            ))
        }
    };
    Ok(Rar20EncodeOptions::new(candidates)
        .with_lazy_matching(true)
        // The audio trial is a second encode of the member, which is the one
        // thing level 1 is trying not to pay for.
        .with_try_audio(level > 1))
}

fn rar20_encode_options_for_options(options: WriterOptions) -> Result<Rar20EncodeOptions> {
    Ok(rar20_encode_options_for_level(options.compression_level)?
        .with_max_match_distance(dictionary_size_for_options(options)?))
}

fn rar15_encode_options_for_level(level: Option<u8>) -> Result<Rar15EncodeOptions> {
    let level = level.unwrap_or(5);
    match level {
        0 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(0)),
        1 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(4 * 1024)),
        2 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(8 * 1024)),
        3 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024)),
        4 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(24 * 1024)),
        5 => Ok(Rar15EncodeOptions::new().with_lazy_matching(false)),
        _ => Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        )),
    }
}

/// The smallest and largest dictionary worth declaring for a target.
///
/// RAR 1.5 and older ignore the field: their decoders have a fixed window, and
/// measuring confirms the packed size does not move with it, so those stay
/// pinned. WinRAR 1.54 writes 64K in every archive we have from it.
fn dictionary_range(target: ArchiveVersion) -> (usize, usize) {
    match target {
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            (128 * 1024, RAR29_MAX_DICTIONARY_SIZE)
        }
        ArchiveVersion::Rar20 => (64 * 1024, RAR29_MAX_DICTIONARY_SIZE),
        _ => (64 * 1024, 64 * 1024),
    }
}

/// The smallest dictionary the format encodes that reaches past `content`, so a
/// match can span everything the window is meant to cover.
///
/// Picking one number for every archive is the wrong shape: too small loses
/// half the ratio on content whose repeats sit far apart, and too large costs a
/// decoder memory it never needs for a thirty byte file. WinRAR sizes it to the
/// data, and reading the dictionary bits out of its own archives against their
/// largest member shows exactly this rule:
///
/// ```text
/// content   130048   196608   262144   705644   1048576
/// declared    128K     256K     512K    1024K     2048K
/// ```
fn fitted_dictionary_size(target: ArchiveVersion, content: u64) -> usize {
    let (floor, cap) = dictionary_range(target);
    let mut size = floor;
    while size < cap && size as u64 <= content {
        size *= 2;
    }
    size
}

fn rar29_default_dictionary_size(target: ArchiveVersion) -> usize {
    match target {
        ArchiveVersion::Rar29 => 1024 * 1024,
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 128 * 1024,
        _ => 64 * 1024,
    }
}

fn dictionary_size_for_options(options: WriterOptions) -> Result<usize> {
    options
        .dictionary_size
        .map(Ok)
        .unwrap_or_else(|| Ok(rar29_default_dictionary_size(options.target)))
}

fn dictionary_flags_for_options(options: WriterOptions) -> Result<u16> {
    dictionary_flags_for_size(dictionary_size_for_options(options)?)
}

fn dictionary_flags_for_size(size: usize) -> Result<u16> {
    let bits =
        match size {
            0x1_0000 => 0,
            0x2_0000 => 1,
            0x4_0000 => 2,
            0x8_0000 => 3,
            0x10_0000 => 4,
            0x20_0000 => 5,
            0x40_0000 => 6,
            _ => return Err(Error::InvalidHeader(
                "RAR 1.5-4.x dictionary size must be one of 64K, 128K, 256K, 512K, 1M, 2M, or 4M",
            )),
        };
    Ok((bits as u16) << 5)
}

fn compression_method_for_level(options: WriterOptions) -> Result<u8> {
    let Some(level) = options.compression_level else {
        return Ok(0x33);
    };
    if level > 5 {
        return Err(Error::InvalidHeader(
            "RAR compression level must be in the range 0..5",
        ));
    }
    if level == 0 {
        return Ok(0x30);
    }
    if matches!(
        options.target,
        ArchiveVersion::Rar20
            | ArchiveVersion::Rar15
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Ok(0x30 + level);
    }
    Ok(0x33)
}

enum SolidEncoder {
    Rar15(Box<Unpack15Encoder>),
    Rar20(Unpack20Encoder),
    Rar29(Unpack29Encoder),
}

impl SolidEncoder {
    fn for_target(options: WriterOptions, solid: bool) -> Result<Option<Self>> {
        if !solid {
            return Ok(None);
        }
        let encoder = match options.target {
            ArchiveVersion::Rar15 => Self::Rar15(Box::new(Unpack15Encoder::with_options(
                rar15_encode_options_for_level(options.compression_level)?,
            ))),
            ArchiveVersion::Rar20 => Self::Rar20(Unpack20Encoder::with_options(
                rar20_encode_options_for_options(options)?,
            )),
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => Self::Rar29(
                Unpack29Encoder::with_options(rar29_encode_options_for_options(options)?),
            ),
            _ => return Ok(None),
        };
        Ok(Some(encoder))
    }
}

struct EncodedPayload {
    data: Vec<u8>,
    method: u8,
}

/// Codes a filtered member, continuing the solid chain when there is one.
///
/// A filtered member used to be coded on its own whatever the archive said,
/// while its header still claimed to continue the chain. That cost the whole
/// benefit of `--solid`: three 400 KB members went from 550 KB to 1.2 MB, and
/// the flag on the members was a plain lie about how they had been coded.
fn encode_filtered_payload(
    data: &[u8],
    policy: &FilterPolicy,
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
) -> Result<EncodedPayload> {
    let lz_method = compression_method_for_level(options)?;
    let codes_through_the_chain = lz_method != 0x30
        && options.method != Rar29Method::Ppmd
        && !matches!(policy, FilterPolicy::Auto)
        && matches!(solid_encoder, Some(SolidEncoder::Rar29(_)));
    if !codes_through_the_chain {
        return encode_rar29_policy_filtered_payload(
            data,
            policy,
            options.method,
            rar29_encode_options_for_options(options)?,
            lz_method,
            ppmd_trial_pays(lz_method.saturating_sub(0x30)),
        );
    }

    let Some(SolidEncoder::Rar29(encoder)) = solid_encoder.as_mut() else {
        unreachable!("the chain was just checked for a RAR 2.9 encoder");
    };
    // An empty member has no range to filter, and `--no-filter` asked for none,
    // but both still go through the chain's encoder like any other member.
    // Coding either one on its own would leave the encoder's history in place
    // while the headers said the chain had ended, so the member after it would
    // be coded against a dictionary its own flags told the decoder to discard.
    let packed = match policy {
        FilterPolicy::Explicit(filter) if !data.is_empty() => {
            encoder.encode_member_with_filters(data, std::slice::from_ref(filter))?
        }
        _ => encoder.encode_member(data)?,
    };

    // A member the encoder could not shrink is stored, exactly as an unfiltered
    // one is, which rebuilds the encoder and ends the chain here.
    if should_store_fallback(options.target, true, data.len(), packed.len()) {
        *solid_encoder = SolidEncoder::for_target(options, true)?;
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: packed,
        method: lz_method,
    })
}

fn encode_or_store_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedPayload> {
    let target = options.target;
    if options.compression_level == Some(0) {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    let solid = solid_encoder.is_some();
    if !solid
        && matches!(
            target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        )
    {
        let encode_options = rar29_encode_options_for_options(options)?;
        let lz_method = compression_method_for_level(options)?;
        // Forcing PPMd leaves nothing for a filter search to measure against.
        let policy = if options.method == Rar29Method::Ppmd {
            FilterPolicy::None
        } else {
            FilterPolicy::Auto
        };
        return encode_rar29_policy_filtered_payload(
            data,
            &policy,
            options.method,
            encode_options,
            lz_method,
            ppmd_trial_pays(lz_method.saturating_sub(0x30)),
        );
    }
    let compressed = encode_compressed_payload(data, options, solid_encoder.as_mut(), progress)?;
    if should_store_fallback(target, solid, data.len(), compressed.len()) {
        if solid {
            *solid_encoder = SolidEncoder::for_target(options, true)?;
        }
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: compressed,
        method: compression_method_for_level(options)?,
    })
}

fn encode_compressed_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: Option<&mut SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<u8>> {
    let target = options.target;
    let mut last = 0usize;
    let mut advance = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    };
    match (target, solid_encoder) {
        (ArchiveVersion::Rar15, Some(SolidEncoder::Rar15(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (ArchiveVersion::Rar15, None) => unpack15_encode_with_options_and_progress(
            data,
            rar15_encode_options_for_level(options.compression_level)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, None) => unpack20_encode_auto_with_options_and_progress(
            data,
            rar20_encode_options_for_options(options)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, Some(SolidEncoder::Rar20(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40, None) => {
            unpack29_encode_literals_with_options_and_progress(
                data,
                Rar29EncodeOptions::default(),
                &mut advance,
            )
            .map_err(map_codec_cancel)
        }
        (
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40,
            Some(SolidEncoder::Rar29(encoder)),
        ) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn map_codec_cancel(error: crate::codec::Error) -> Error {
    if error == crate::codec::Error::Cancelled {
        Error::Cancelled
    } else {
        Error::from(error)
    }
}

fn should_store_fallback(
    target: ArchiveVersion,
    solid: bool,
    unpacked_len: usize,
    packed_len: usize,
) -> bool {
    // RAR 2.0 onwards store any member compression did not help. RAR 1.5 pays
    // more header for a stored member, so a small one stays compressed.
    let stores_any_size = !solid
        && matches!(
            target,
            ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        );
    // Storing a member part way through a solid run rebuilds the encoder, so
    // the member after it has to say it starts a fresh chain. Only RAR 2.0
    // onwards can: RAR 1.5 file headers have no solid bit, and readers take
    // every member of a solid RAR 1.5 archive as a continuation whatever the
    // header says. Breaking the chain there writes an archive nothing can read.
    crate::write_plan::StoreFallback::new()
        .allow_solid(target != ArchiveVersion::Rar15)
        .min_size(if stores_any_size {
            0
        } else {
            MIN_STORE_FALLBACK_SIZE
        })
        .applies(solid, unpacked_len, packed_len)
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some()
        && !matches!(
            options.target,
            ArchiveVersion::Rar15
                | ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        )
    {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 2.9 encrypted volume writer",
        });
    }
    if file_comment.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    Ok(())
}

fn writer_file_flags(
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    solid_continuation: bool,
) -> u16 {
    let mut flags = 0;
    if password.is_some() {
        flags |= FHD_PASSWORD;
    }
    if file_comment.is_some() {
        flags |= FHD_COMMENT;
    }
    if solid_continuation {
        flags |= FHD_SOLID;
    }
    flags
}

/// Builds the comment block that goes inside a file header.
///
/// RAR 1.3 and 1.4 wrote a bare size and the text, and this writer used to copy
/// that. From 1.5 on it is the same comment block the archive comment uses,
/// covered by the file header's size but not by its CRC.
fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_comment_header(&mut out, comment)?;
    Ok(out)
}

fn encrypt_split_packed_data(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: &[u8],
) -> Result<Option<[u8; 8]>> {
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data)?;
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt))
                .map_err(super::map_rar30_crypto_error)?
                .encrypt_in_place(data)
                .map_err(super::map_rar30_crypto_error)?;
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn writer_supports_file_encryption(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    )
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = Option<&'a [u8]>>,
) -> Result<&'a [u8]> {
    let first = passwords.next().flatten().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != Some(first) {
            return Err(Error::InvalidHeader(
                "RAR 3.x header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn encrypt_packed_data_for_writer(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: Option<&[u8]>,
) -> Result<Option<[u8; 8]>> {
    let Some(password) = password else {
        return Ok(None);
    };
    validate_writer_password(target, Some(password))?;
    match target {
        ArchiveVersion::Rar15 => {
            Rar15Cipher::new(password).crypt_in_place(data);
            Ok(None)
        }
        ArchiveVersion::Rar20 => {
            let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)?;
            data.resize(padded_len, 0);
            Rar20Cipher::new(password).encrypt_in_place(data)?;
            Ok(None)
        }
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            let salt = random_rar30_salt()?;
            let padded_len =
                data.len()
                    .checked_add(15)
                    .map(|len| len & !15)
                    .ok_or(Error::InvalidHeader(
                        "RAR 3.x encrypted data size overflows",
                    ))?;
            data.resize(padded_len, 0);
            Rar30Cipher::new(password, Some(salt))
                .map_err(super::map_rar30_crypto_error)?
                .encrypt_in_place(data)
                .map_err(super::map_rar30_crypto_error)?;
            Ok(Some(salt))
        }
        _ => Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        }),
    }
}

fn random_rar30_salt() -> Result<[u8; 8]> {
    let mut salt = [0; 8];
    getrandom::fill(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 3.x writer could not generate encryption salt"))?;
    Ok(salt)
}

/// What WinRAR writes on an end-of-archive block. The bit marks the block as
/// one a reader may skip without understanding it.
const ENDARC_FLAGS: u16 = 0x4000;
const END_HEADER_SIZE: usize = 7;

fn write_main_header(out: &mut Vec<u8>, flags: u16) {
    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(MAIN_HEAD);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&13u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    write_header_crc(out, start);
}

fn write_comment_header(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let unp_size = u16::try_from(comment.len())
        .map_err(|_| Error::InvalidHeader("RAR 1.5 comment is longer than 65535 bytes"))?;
    let head_size = 13usize
        .checked_add(comment.len())
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 comment header size overflows",
        ))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 comment header size overflows"))?;

    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(COMM_HEAD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&unp_size.to_le_bytes());
    out.push(15);
    out.push(0x30);
    out.extend_from_slice(&((crc32(comment) & 0xffff) as u16).to_le_bytes());
    out.extend_from_slice(comment);
    write_comment_header_crc(out, start);
    Ok(())
}

fn uses_old_style_archive_comment(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
    )
}

fn write_archive_comment(
    out: &mut Vec<u8>,
    comment: Option<&[u8]>,
    target: ArchiveVersion,
) -> Result<()> {
    if uses_old_style_archive_comment(target) {
        return write_comment_header(out, comment);
    }
    match target {
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => write_newsub_archive_comment(out, comment),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn write_newsub_archive_comment(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let packed = unpack29_encode_literals(comment)?;
    write_file_header_and_data(
        out,
        FileRecord {
            head_type: NEWSUB_HEAD,
            name: b"CMT",
            unpacked_size: comment.len(),
            file_crc: crc32(comment),
            packed_size: packed.len(),
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            target: ArchiveVersion::Rar30,
            method: 0x33,
            dictionary_flags: dictionary_flags_for_target(ArchiveVersion::Rar30),
            flags: 0,
            salt: None,
            extra: &[],
        },
        &packed,
    )
}

/// Closes a header-encrypted archive with an end-of-archive block in a group of
/// its own.
///
/// Every encrypted header carries its own salt, so a reader that reaches the end
/// of the last member's payload reads eight more bytes looking for the next
/// group's salt. With nothing there it stops on a short read rather than on a
/// clean end, and 7-Zip treats that as a decryption failure and refuses to open
/// the archive at all. WinRAR closes the same way. unrar stops at the last
/// member and never looks, which is why nothing caught this.
fn write_encrypted_end_block(out: &mut dyn Write, password: &[u8]) -> Result<()> {
    let mut header = Vec::new();
    let start = header.len();
    header.extend_from_slice(&0u16.to_le_bytes());
    header.push(ENDARC_HEAD);
    header.extend_from_slice(&ENDARC_FLAGS.to_le_bytes());
    header.extend_from_slice(&(END_HEADER_SIZE as u16).to_le_bytes());
    write_header_crc(&mut header, start);
    debug_assert_eq!(header.len(), END_HEADER_SIZE);
    write_encrypted_header(out, &header, password)
}

fn write_encrypted_header(out: &mut dyn Write, header: &[u8], password: &[u8]) -> Result<()> {
    let salt = random_rar30_salt()?;
    let encrypted_size = checked_align16(header.len(), RAR15_ALIGN_OVERFLOW)?;
    let mut encrypted_header = Vec::with_capacity(encrypted_size);
    encrypted_header.extend_from_slice(header);
    encrypted_header.resize(encrypted_size, 0);
    Rar30Cipher::new(password, Some(salt))
        .map_err(super::map_rar30_crypto_error)?
        .encrypt_in_place(&mut encrypted_header)
        .map_err(super::map_rar30_crypto_error)?;
    out.write_all(&salt)?;
    out.write_all(&encrypted_header)?;
    Ok(())
}

fn validate_writer_password(target: ArchiveVersion, password: Option<&[u8]>) -> Result<()> {
    if password.is_some() && !writer_supports_file_encryption(target) {
        return Err(Error::UnsupportedFeature {
            version: target,
            feature: "RAR writer file encryption",
        });
    }
    Ok(())
}

fn validate_member(name: &[u8], unpacked_size: usize) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 file name is empty"));
    }
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader("RAR 1.5 file name is too long"));
    }
    if unpacked_size > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.5 writer does not support large files",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    validate_member(name, data.len())
}

struct FileRecord<'a> {
    head_type: u8,
    name: &'a [u8],
    unpacked_size: usize,
    file_crc: u32,
    packed_size: usize,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    dictionary_flags: u16,
    flags: u16,
    salt: Option<[u8; 8]>,
    extra: &'a [u8],
}

fn write_file_header_and_data(
    out: &mut Vec<u8>,
    record: FileRecord<'_>,
    packed: &[u8],
) -> Result<()> {
    write_file_header(out, &record)?;
    out.extend_from_slice(packed);
    Ok(())
}

fn write_file_header(out: &mut Vec<u8>, record: &FileRecord<'_>) -> Result<()> {
    let start = out.len();
    let flags = record.flags | record.dictionary_flags;
    let (host_os, file_attr) =
        rar15_compatible_metadata(record.target, record.host_os, record.file_attr);
    let packed_size = u32::try_from(record.packed_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed size overflows u32"))?;
    let unpacked_size = u32::try_from(record.unpacked_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows u32"))?;
    let head_size = 32usize
        .checked_add(record.name.len())
        .and_then(|size| size.checked_add(if record.salt.is_some() { 8 } else { 0 }))
        .and_then(|size| size.checked_add(record.extra.len()))
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    let unp_ver = match record.target {
        ArchiveVersion::Rar15 => 15,
        ArchiveVersion::Rar20 => 20,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 29,
        _ => return Err(Error::UnsupportedVersion(record.target)),
    };
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(record.head_type);
    out.extend_from_slice(&(LONG_BLOCK | flags).to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&packed_size.to_le_bytes());
    out.extend_from_slice(&unpacked_size.to_le_bytes());
    out.push(host_os);
    out.extend_from_slice(&record.file_crc.to_le_bytes());
    out.extend_from_slice(&record.file_time.to_le_bytes());
    out.push(unp_ver);
    out.push(record.method);
    out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&file_attr.to_le_bytes());
    out.extend_from_slice(record.name);
    if let Some(salt) = record.salt {
        out.extend_from_slice(&salt);
    }
    out.extend_from_slice(record.extra);
    write_file_header_crc(out, start, record.name.len(), flags);
    Ok(())
}

fn rar15_compatible_metadata(target: ArchiveVersion, host_os: u8, file_attr: u32) -> (u8, u32) {
    const HOST_DOS: u8 = 0;
    const HOST_UNIX: u8 = 3;
    const DOS_ARCHIVE: u32 = 0x20;
    const DOS_DIRECTORY: u32 = 0x10;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_DIRECTORY: u32 = 0o040000;

    if target == ArchiveVersion::Rar15 && host_os == HOST_UNIX {
        let dos_attr = if file_attr & UNIX_FILE_TYPE_MASK == UNIX_DIRECTORY {
            DOS_DIRECTORY
        } else {
            DOS_ARCHIVE
        };
        return (HOST_DOS, dos_attr);
    }
    (host_os, file_attr)
}

fn dictionary_flags_for_target(target: ArchiveVersion) -> u16 {
    ((rar29_default_dictionary_size(target).trailing_zeros() - 16) as u16) << 5
}

struct SplitVolumeRecord<'a> {
    name: &'a [u8],
    unpacked: &'a [u8],
    packed: &'a [u8],
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    dictionary_flags: u16,
    base_flags: u16,
    main_flags: u16,
    password: Option<&'a [u8]>,
    max_packed_per_volume: usize,
}

fn write_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = if let Some(password) = entry.password {
        encrypt_split_packed_data(&mut packed, entry.target, password)?
    } else {
        None
    };
    let base_flags = entry.base_flags | if split_salt.is_some() { FHD_SALT } else { 0 };

    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        write_file_header_and_data(
            &mut out,
            FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed_size: chunk.len(),
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                dictionary_flags: entry.dictionary_flags,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
            chunk,
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn write_header_encrypted_split_volumes(entry: SplitVolumeRecord<'_>) -> Result<Vec<Vec<u8>>> {
    validate_header_encrypted_archive_options(entry.target, false, entry.password.is_some())?;
    let password = entry.password.ok_or(Error::NeedPassword)?;
    if entry.max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume payload size must be non-zero",
        ));
    }
    if entry.packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        ));
    }

    let mut packed = entry.packed.to_vec();
    let split_salt = encrypt_split_packed_data(&mut packed, entry.target, password)?;
    let base_flags = entry.base_flags | FHD_SALT;
    let chunks: Vec<&[u8]> = packed.chunks(entry.max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    let unpacked_crc = crc32(entry.unpacked);
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut file_flags = base_flags;
        if split_before {
            file_flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            file_flags |= FHD_SPLIT_AFTER;
        }

        let mut main_flags = MHD_VOLUME | MHD_PASSWORD | entry.main_flags;
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }

        let mut out = Vec::new();
        out.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut out, main_flags);
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            &FileRecord {
                head_type: FILE_HEAD,
                name: entry.name,
                unpacked_size: entry.unpacked.len(),
                file_crc: if split_after {
                    crc32(chunk)
                } else {
                    unpacked_crc
                },
                packed_size: chunk.len(),
                file_time: entry.file_time,
                file_attr: entry.file_attr,
                host_os: entry.host_os,
                target: entry.target,
                method: entry.method,
                dictionary_flags: entry.dictionary_flags,
                flags: file_flags,
                salt: split_salt,
                extra: &[],
            },
        )?;
        write_encrypted_header(&mut out, &header, password)?;
        out.extend_from_slice(chunk);
        volumes.push(out);
    }

    Ok(volumes)
}

fn write_header_crc(out: &mut [u8], start: usize) {
    let crc = (crc32(&out[start + 2..]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_file_header_crc(out: &mut [u8], start: usize, name_len: usize, flags: u16) {
    let end = if flags & FHD_COMMENT != 0 {
        // Readers stop the CRC where the fields they parse stop, which leaves
        // out the comment block. Miss the salt out of the range and an
        // encrypted member with a comment gets a CRC nothing agrees with.
        let salt_len = if flags & FHD_SALT != 0 { 8 } else { 0 };
        start + 32 + name_len + salt_len
    } else {
        out.len()
    };
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_comment_header_crc(out: &mut [u8], start: usize) {
    let end = start + 13;
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        encode_rar29_auto_filtered_member, encode_rar29_filtered_member,
        encode_rar29_filtered_members, is_audio_filter_candidate, rar20_encode_options_for_options,
        rar29_encode_options_for_options, FilterKind, FilterSpec,
    };
    use crate::codec::rar29::{unpack29_decode, EncodeOptions};

    /// A member comfortably past the 1 MiB ceiling the PPMd trial used to have.
    /// Text this size kept the LZ bytes without PPMd ever being encoded to
    /// compare against, all the way up to 16 MiB.
    const OVER_THE_OLD_TRIAL_LIMIT: usize = 1024 * 1024 + 4096;
    use crate::filter_search::{
        auto_delta_filter_range, disjoint_filter_ranges, AUTO_DELTA_EDGE_SKIP,
    };
    use crate::x86_filter_scan::auto_x86_filter_ranges;
    use crate::{ArchiveVersion, FeatureSet};

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0x41; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }
        for pos in [12_000, 12_040, 12_080] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert_eq!(e8_ranges.len(), 1);
        assert!(e8_ranges[0].contains(&1024));
        assert!(e8_ranges[0].contains(&(1130 + 4)));
        assert!(!e8_ranges[0].contains(&12_000));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert_eq!(e8e9_ranges.len(), 3);
        assert!(e8e9_ranges[0].contains(&1024));
        assert!(e8e9_ranges[0].contains(&12_000));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&1024)));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&12_000)));
    }

    #[test]
    fn large_text_ppmd_candidate_accepts_html_like_payloads() {
        let mut data = vec![b'a'; OVER_THE_OLD_TRIAL_LIMIT];
        for index in (0..data.len()).step_by(79) {
            data[index] = b'\n';
        }
        data[..32].copy_from_slice(b"<html><body>RAR PPMd text sample");

        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// Reading past padding leaves the question of a member that is nothing
    /// else. There is no evidence either way in it, and PPMd is not the answer
    /// to a member the store rule is about to take anyway.
    #[test]
    fn a_member_of_nothing_but_padding_is_not_text() {
        let data = vec![0u8; OVER_THE_OLD_TRIAL_LIMIT];

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// Scattered NULs are not padding and still count against the member: a
    /// run has to be long enough to be structure before it is discounted.
    #[test]
    fn scattered_nuls_still_read_as_binary() {
        let mut data = vec![b'A'; OVER_THE_OLD_TRIAL_LIMIT];
        for index in (0..data.len()).step_by(3) {
            data[index] = 0;
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// The bench corpus is man pages in several languages, and counting only
    /// ASCII scored the sample 77% against an 85% bar and sent it to LZ.
    #[test]
    fn the_text_screen_reads_multibyte_utf8_as_text() {
        let line = "Überprüfen Sie die Größe der Datei — ändern Sie sie nicht. \
                    日本語のマニュアルページもテキストです。\n";
        let data = line.repeat(4096).into_bytes();

        let high = data.iter().filter(|&&byte| byte >= 0x80).count();
        assert!(
            high * 100 / data.len() > 15,
            "sample must be multibyte enough to have failed the ASCII-only test"
        );
        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// Accepting multibyte sequences must not accept binary that happens to
    /// contain a few: a lead byte followed by a continuation byte turns up at
    /// random often enough to notice, nowhere near often enough to pass.
    #[test]
    fn the_text_screen_still_rejects_high_entropy_binary() {
        let mut state = 0x1234_5678u32;
        let data: Vec<_> = (0..64_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// A tar pads every member to a 512 byte block and closes with a block of
    /// nothing, which is 27% NUL in front of a 1% bar. The source tree in the
    /// bench corpus was read as binary and packed 22% behind WinRAR 3.00 for it.
    #[test]
    fn the_text_screen_reads_past_tar_padding() {
        let mut data = Vec::new();
        for index in 0..512 {
            let mut header = vec![0u8; 512];
            let name = format!("src/module{index}.rs");
            header[..name.len()].copy_from_slice(name.as_bytes());
            data.extend_from_slice(&header);
            let body = format!(
                "pub fn thing{index}(value: usize) -> usize {{\n    value.wrapping_mul({index})\n}}\n"
            );
            data.extend_from_slice(body.as_bytes());
            // Every member is padded out to the next block boundary.
            data.resize(data.len().next_multiple_of(512), 0);
        }
        data.extend_from_slice(&[0u8; 1024]);

        let nul = data.iter().filter(|&&byte| byte == 0).count();
        assert!(
            nul * 100 / data.len() > 15,
            "the padding has to be heavy enough to have failed the old rule"
        );
        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// The other side of that: an object file is full of NUL runs too, and
    /// reading past them must not turn its code into text. A member wrongly
    /// called text skips the x86 filter search, so this one costs bytes.
    #[test]
    fn reading_past_padding_does_not_make_an_object_file_text() {
        let mut state = 0x8badf00du32;
        let mut data = Vec::new();
        for section in 0..64 {
            // Alignment padding, the way a linker leaves it.
            data.resize(data.len() + 64, 0);
            data.extend_from_slice(format!("_ZN4rars{section}E\0").as_bytes());
            for _ in 0..1024 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                data.push(state as u8);
            }
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// Naming the level you were already getting must not change the archive.
    /// The default resolves to method 0x33, the same as `--level 3`, but the
    /// trial decision read the option rather than the level and the two came
    /// out 24% apart on the same text.
    #[test]
    fn the_default_level_and_level_three_agree_about_the_ppmd_trial() {
        let options = crate::rar15_40::WriterOptions {
            target: crate::ArchiveVersion::Rar30,
            ..Default::default()
        };
        let default_level = super::compression_method_for_level(options).unwrap();
        let named_level = super::compression_method_for_level(crate::rar15_40::WriterOptions {
            compression_level: Some(3),
            ..options
        })
        .unwrap();

        assert_eq!(default_level, named_level);
        assert_eq!(
            super::ppmd_trial_pays(default_level - 0x30),
            super::ppmd_trial_pays(named_level - 0x30),
        );
        assert!(super::ppmd_trial_pays(3));
        assert!(!super::ppmd_trial_pays(2));
    }

    #[test]
    fn auto_ppmd_candidate_rejects_binary_audio_shaped_payloads() {
        let mut data = Vec::new();
        for sample in 0..8192i16 {
            let left = sample.wrapping_mul(5).wrapping_add(200);
            let right = sample.wrapping_mul(7).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    #[test]
    fn auto_ppmd_candidate_accepts_text_payloads() {
        let data = b"fn main() {\n    println!(\"rar ppmd text candidate\");\n}\n".repeat(256);

        assert!(super::is_text_ppmd_candidate(&data));
    }

    #[test]
    fn audio_filter_candidate_accepts_interleaved_pcm_like_payloads() {
        let mut data = Vec::new();
        for sample in 0..4096i16 {
            let left = sample.wrapping_mul(3).wrapping_add(200);
            let right = sample.wrapping_mul(3).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(is_audio_filter_candidate(&data, 4));
        assert!(!is_audio_filter_candidate(&data, 3));
    }

    #[test]
    fn audio_filter_candidate_rejects_high_entropy_binary_payloads() {
        let mut state = 0xfeed_faceu32;
        let data: Vec<_> = (0..16_384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        for channels in 1..=4 {
            assert!(!is_audio_filter_candidate(&data, channels));
        }
    }

    /// Prose with no long repeats: PPMd's model has plenty to work with and LZ
    /// has little to match, which is the shape the engine choice exists for.
    fn prose_like_text(len: usize) -> Vec<u8> {
        const WORDS: [&str; 24] = [
            "archive",
            "compression",
            "dictionary",
            "encoder",
            "filter",
            "header",
            "member",
            "method",
            "offset",
            "payload",
            "reader",
            "solid",
            "stream",
            "volume",
            "window",
            "writer",
            "the",
            "of",
            "a",
            "and",
            "to",
            "in",
            "that",
            "with",
        ];
        let mut state = 0x9e37_79b9u32;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.extend_from_slice(WORDS[state as usize % WORDS.len()].as_bytes());
            out.push(if state.is_multiple_of(13) {
                b'\n'
            } else {
                b' '
            });
        }
        out.truncate(len);
        out
    }

    /// Text past the trial limit used to keep the LZ bytes without ever
    /// encoding PPMd to compare, which cost 24% on 2 MiB of man pages and 12%
    /// on 4 MiB. The method byte cannot tell the two engines apart (PPMd and
    /// `-m5` LZ both write 0x35), so ask for the member both ways instead.
    #[test]
    fn text_over_the_trial_limit_is_measured_against_ppmd() {
        let data = prose_like_text(OVER_THE_OLD_TRIAL_LIMIT);
        assert!(super::is_text_ppmd_candidate(&data));

        let offered =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, true).unwrap();
        let lz_only =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
                .unwrap();

        assert!(
            offered.data.len() < lz_only.data.len(),
            "PPMd should have won this member: offered {} bytes, LZ alone {}",
            offered.data.len(),
            lz_only.data.len()
        );
    }

    /// The other half of the same rule: winning is measured, not assumed. Text
    /// that is one phrase repeating is all match and belongs to LZ, and the
    /// member has to come back no larger than LZ alone would have made it.
    #[test]
    fn text_ppmd_cannot_lose_to_the_engine_it_replaced() {
        let data = b"the quick brown fox jumps over the lazy dog. "
            .repeat(OVER_THE_OLD_TRIAL_LIMIT / 45 + 64);
        assert!(super::is_text_ppmd_candidate(&data));

        let offered =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, true).unwrap();
        let lz_only =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
                .unwrap();

        assert!(
            offered.data.len() <= lz_only.data.len(),
            "offering PPMd made the member bigger: {} bytes against {}",
            offered.data.len(),
            lz_only.data.len()
        );
    }

    #[test]
    fn auto_x86_filter_ranges_include_code_section_spans() {
        let mut data = vec![0x41; 32_000];
        for pos in [4096, 4128, 4160] {
            data[pos] = 0xe8;
        }
        for pos in [14_000, 14_032, 14_064] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert!(ranges[0].contains(&4096));
        assert!(ranges[0].contains(&14_064));
        assert!(ranges.iter().any(|range| range.contains(&4096)));
        assert!(ranges.iter().any(|range| range.contains(&14_064)));
    }

    #[test]
    fn auto_x86_policy_can_encode_multiple_disjoint_ranges() {
        let mut data = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                data[pos] = 0xe8;
                data[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }
        let filters: Vec<_> = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false))
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();

        let packed = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("multi-filter RAR29 member should encode");
        let decoded = unpack29_decode(&packed, data.len()).unwrap();

        assert_eq!(filters.len(), 2);
        assert!(
            decoded == data,
            "RAR 2.9 auto multi-filter E8 round-trip failed"
        );
    }

    #[test]
    fn auto_x86_policy_considers_tight_ranges_inside_sparse_spans() {
        let mut data = Vec::new();
        data.extend((0..1024).map(|index| (index * 37 + 11) as u8));
        let first_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = first_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
        }
        data.extend((0..3200).map(|index| (index * 251 + 17) as u8));
        let second_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x56, 0x8b, 0xf1, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = second_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5e, 0xc3]);
        }
        data.extend((0..1024).map(|index| (index * 53 + 7) as u8));

        let ranges = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false));
        let filters: Vec<_> = ranges
            .iter()
            .cloned()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();
        let broad_range = first_cluster_start..second_cluster_start + 16 * 16;
        let broad = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(FilterKind::E8, broad_range),
            EncodeOptions::default(),
        )
        .unwrap();
        let tight = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("tight sparse x86 filters should encode");
        let auto = encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
            .unwrap();

        assert!(
            tight.len() < broad.len(),
            "tight x86 ranges should avoid filtering sparse data gaps"
        );
        assert!(auto.data.len() <= tight.len());
        assert_eq!(unpack29_decode(&auto.data, data.len()).unwrap(), data);
    }

    #[test]
    fn auto_delta_filter_range_skips_container_edges_and_aligns_channels() {
        let data = vec![0u8; 512];

        let range = auto_delta_filter_range(&data, 3).unwrap();

        assert!(range.start >= AUTO_DELTA_EDGE_SKIP);
        assert!(range.end <= data.len() - AUTO_DELTA_EDGE_SKIP);
        assert_eq!(range.start % 3, 0);
        assert_eq!((range.end - range.start) % 3, 0);
        assert!(auto_delta_filter_range(&data[..80], 3).is_none());
    }

    #[test]
    fn auto_filter_policy_considers_ranged_delta_candidates() {
        let mut data = vec![0x55u8; AUTO_DELTA_EDGE_SKIP];
        for sample in 0..256u16 {
            let left = sample as u8;
            let right = left.wrapping_add(1);
            data.extend_from_slice(&[left, right]);
        }
        data.extend(std::iter::repeat_n(0xaa, AUTO_DELTA_EDGE_SKIP));
        let options = EncodeOptions::default();

        let plain =
            crate::codec::rar29::unpack29_encode_literals_with_options(&data, options).unwrap();
        let ranged = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(
                FilterKind::Delta { channels: 2 },
                auto_delta_filter_range(&data, 2).unwrap(),
            ),
            options,
        )
        .unwrap();
        let auto = encode_rar29_auto_filtered_member(&data, options, 0x35, true).unwrap();

        assert!(ranged.len() < plain.len());
        assert!(auto.data.len() <= ranged.len());
    }

    #[test]
    fn rar29_options_cap_match_distance_to_target_dictionary() {
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            1024 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            128 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
                    .with_dictionary_size(4 * 1024 * 1024)
            )
            .unwrap()
            .max_match_distance,
            4 * 1024 * 1024
        );
    }

    #[test]
    fn rar20_options_cap_match_distance_to_header_dictionary() {
        assert_eq!(
            rar20_encode_options_for_options(super::WriterOptions::new(
                ArchiveVersion::Rar20,
                FeatureSet::store_only(),
            ))
            .unwrap()
            .max_match_distance,
            64 * 1024
        );
        assert_eq!(
            rar20_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only())
                    .with_dictionary_size(1024 * 1024),
            )
            .unwrap()
            .max_match_distance,
            1024 * 1024
        );
    }
}
