//! The parallel extraction driver shared by every format that has one.
//!
//! Members are handled in archive order. A member a worker can decode alone
//! and cheaply joins a batch. Any other member (split, too large to buffer)
//! is decoded inline on the calling thread, after the batches before it have
//! been published. One large member therefore does not serialize the whole
//! archive, and inline members leave the worker pool idle for any parallelism
//! inside their own decode.

use crate::codec::workspace::{Buffer, Limited};
use crate::read_control::ReadControl;
use crate::{Error, Result};
use std::cell::Cell;
use std::io::Write;

/// Archive-wide byte budget for a batch of legacy members whose decoded output
/// is buffered for in-order publication. Larger members stream inline.
pub(crate) const LEGACY_BATCH_BYTES: u64 = 16 * 1024 * 1024;

/// How the driver handles one member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Decode on a worker. The cost counts against the batch's byte budget.
    Batch(u64),
    /// Decode on the calling thread, between batches.
    Inline,
}

/// Feeds each run of batchable members to `batches` and each inline member to
/// `inline`, in archive order. `ctx` is the state both share, such as the
/// caller's writer factory. `batches` returns how many members it published;
/// a member refused within a worker's share of the workspace goes inline, and
/// the members after it are batched again.
pub(crate) fn run<T: Copy, C: ?Sized>(
    items: impl IntoIterator<Item = T>,
    ctx: &mut C,
    mut plan: impl FnMut(T) -> Plan,
    mut batches: impl FnMut(&mut C, &[(T, u64)]) -> Result<usize>,
    mut inline: impl FnMut(&mut C, T) -> Result<()>,
) -> Result<()> {
    let mut pending = Vec::new();
    for item in items {
        match plan(item) {
            Plan::Batch(cost) => pending.push((item, cost)),
            Plan::Inline => {
                flush(ctx, &pending, &mut batches, &mut inline)?;
                pending.clear();
                inline(ctx, item)?;
            }
        }
    }
    flush(ctx, &pending, &mut batches, &mut inline)
}

fn flush<T: Copy, C: ?Sized>(
    ctx: &mut C,
    mut pending: &[(T, u64)],
    batches: &mut impl FnMut(&mut C, &[(T, u64)]) -> Result<usize>,
    inline: &mut impl FnMut(&mut C, T) -> Result<()>,
) -> Result<()> {
    while !pending.is_empty() {
        let published = batches(ctx, pending)?;
        let Some(&(refused, _)) = pending.get(published) else {
            break;
        };
        inline(ctx, refused)?;
        pending = &pending[published + 1..];
    }
    Ok(())
}

/// What a worker hands back for in-order publication.
pub(crate) enum Decoded<M> {
    /// Nothing to publish, such as a redirection that is not extracted.
    Nothing,
    /// Published by opening its writer: a directory, or a verified member.
    Opened(M),
    /// Decoded output, written once the members before it are published.
    File { meta: M, data: Buffer<u8> },
}

/// Publishes one worker result through `open`. `divert` can take a file's
/// output instead, as legacy symbolic links do; it returns whether it did.
pub(crate) fn publish<M>(
    entry: Decoded<M>,
    open: &mut dyn FnMut(&M) -> Result<Box<dyn Write>>,
    control: &ReadControl,
    name: impl Fn(&M) -> &[u8],
    divert: impl FnOnce(&M, &[u8]) -> Result<bool>,
) -> Result<()> {
    control.check()?;
    match entry {
        Decoded::Nothing => {}
        Decoded::Opened(meta) => {
            open(&meta)?;
        }
        Decoded::File { meta, data } => {
            if divert(&meta, &data)? {
                return Ok(());
            }
            let mut writer = open(&meta)?;
            control.check()?;
            control
                .write_all(&mut writer, &data)
                .map_err(|error| Error::from(error).at_entry(name(&meta).to_vec(), "extracting"))?;
            crate::extraction_control::flush_verified(control, name(&meta), &mut *writer)?;
        }
    }
    control.check()
}

/// Workspace, by the members' hints, that the members an unlimited policy has
/// running may hold together: 1 GiB, or a quarter of the memory this process
/// may use when that is less. Sequential extraction holds one member's; this
/// lets several streaming members, each with its own window, run side by side
/// without one window per thread. One member can always run alone.
pub(crate) fn running_workspace() -> u64 {
    scaled_running_workspace(crate::memory_limit::physical_memory())
}

fn scaled_running_workspace(physical: Option<u64>) -> u64 {
    const CEILING: u64 = 1024 * 1024 * 1024;
    physical.map_or(CEILING, |total| CEILING.min(total / 4))
}

/// What the members a parallel run has admitted hold: the planned cost of
/// the results not yet published, and the workspace of those running, by
/// their hints.
pub(crate) struct Room {
    held: Cell<(u128, u128)>,
    capacity: u64,
    running: u64,
}

impl Room {
    /// Room for results costing `capacity` and members running in `running`.
    pub(crate) fn new(capacity: u64, running: u64) -> Self {
        Self {
            held: Cell::new((0, 0)),
            capacity,
            running,
        }
    }

    /// Whether a member of `cost` that runs in `workspace` may start, and if
    /// so takes its room. One always may when `idle`, with nothing held;
    /// otherwise each must fit, unless nothing of its kind is held.
    pub(crate) fn admit(&self, cost: u64, workspace: u64, idle: bool) -> bool {
        let fits = |held: u128, more: u64, limit: u64| {
            held == 0 || held + u128::from(more) <= u128::from(limit)
        };
        let (bytes, running) = self.held.get();
        let admitted =
            idle || (fits(bytes, cost, self.capacity) && fits(running, workspace, self.running));
        if admitted {
            self.held
                .set((bytes + u128::from(cost), running + u128::from(workspace)));
        }
        admitted
    }

    /// A member admitted with `cost` and `workspace` has finished running. Its
    /// cost stays held until [`Self::published`] if its result is `retained`.
    pub(crate) fn finished(&self, cost: u64, workspace: u64, retained: bool) {
        let (bytes, running) = self.held.get();
        let done = if retained { 0 } else { u128::from(cost) };
        self.held
            .set((bytes - done, running - u128::from(workspace)));
    }

    /// A member's `retained` result of `cost` has been published.
    pub(crate) fn published(&self, cost: u64, retained: bool) {
        if retained {
            let (bytes, running) = self.held.get();
            self.held.set((bytes - u128::from(cost), running));
        }
    }
}

impl Limited {
    /// Decodes `members` on workers and publishes them in archive order. The
    /// members ahead of a failure are published before it returns. Returns how
    /// many were published: fewer than all means the next was refused by a
    /// limited workspace even when it ran alone, so the caller can decode it
    /// another way.
    ///
    /// The workers share this workspace, so a member may be refused only
    /// because others ran beside it. It runs again alone before it is handed
    /// back, and the members after it carry on.
    ///
    /// At most one member runs per worker. The results not yet published
    /// hold at most `capacity` bytes of cost, which a member holds until it is
    /// published, or with `retained` false only while it decodes. The members
    /// running hold, by their hints, at most [`running_workspace`], or what a
    /// limited workspace has free. A member over either waits until that one
    /// is empty. Where this thread may wait on workers, members start as soon
    /// as there is room, so a slow member holds back only the publication of
    /// those after it; otherwise they run a batch at a time.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn batches<T: Copy + Send, O: Send, C: ?Sized>(
        &self,
        members: &[(T, u64)],
        capacity: u64,
        retained: bool,
        ctx: &mut C,
        hint: impl Fn(T) -> u64,
        check: impl Fn() -> Result<()> + Sync,
        decode: impl Fn(T, &Self) -> Result<O> + Sync + Send,
        mut publish: impl FnMut(&mut C, O) -> Result<()>,
    ) -> Result<usize> {
        check()?;
        let window = crate::parallel::default_window().max(1);
        let running = if self.is_limited() {
            self.available()
        } else {
            running_workspace()
        };
        // A refused member is `None`, to run again alone or hand back.
        let decode = |member| {
            check()?;
            match decode(member, self) {
                Err(error) if crate::codec::workspace::is_refusal(&error) => Ok(None),
                decoded => decoded.map(Some),
            }
        };
        let mut published = 0;
        while published < members.len() {
            let rest = &members[published..];
            let (count, refused) = side_by_side(
                rest,
                window,
                Room::new(capacity, running),
                retained,
                &hint,
                &decode,
                &mut |output| publish(ctx, output),
            )?;
            published += count;
            match refused {
                None => break,
                Some(false) => return Ok(published),
                Some(true) => match decode(rest[count].0)? {
                    Some(output) => {
                        publish(ctx, output)?;
                        published += 1;
                    }
                    None => return Ok(published),
                },
            }
        }
        Ok(published)
    }
}

/// Decodes `members` side by side within `room` and publishes them in order,
/// as [`Limited::batches`] does, until one is refused. Returns how many were
/// published, and for the refused member, if any, whether another member ran
/// beside it.
fn side_by_side<T: Copy + Send, O: Send>(
    members: &[(T, u64)],
    window: usize,
    room: Room,
    retained: bool,
    hint: &dyn Fn(T) -> u64,
    decode: &(dyn Fn(T) -> Result<Option<O>> + Sync),
    publish: &mut dyn FnMut(O) -> Result<()>,
) -> Result<(usize, Option<bool>)> {
    let (mut published, mut refused) = (0, None);
    if window > 1 && members.len() > 1 && crate::parallel::may_spawn() {
        // Which members ran beside another, and those running now.
        let shared = std::cell::RefCell::new((vec![false; members.len()], Vec::new()));
        let items: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(index, &(member, _))| (index, member))
            .collect();
        let result = crate::parallel::map_ordered(
            &items,
            window,
            |(index, member), idle| {
                if !room.admit(members[index].1, hint(member), idle) {
                    return false;
                }
                let (beside, running) = &mut *shared.borrow_mut();
                if !running.is_empty() {
                    beside[index] = true;
                    running
                        .iter()
                        .for_each(|&other: &usize| beside[other] = true);
                }
                running.push(index);
                true
            },
            |(index, member)| {
                room.finished(members[index].1, hint(member), retained);
                shared.borrow_mut().1.retain(|&other| other != index);
            },
            |(index, _)| room.published(members[index].1, retained),
            |(index, member)| decode(member).map(|output| (index, output)),
            |(index, output)| {
                let Some(output) = output else {
                    refused = Some(shared.borrow().0[index]);
                    return Err(Error::Cancelled);
                };
                publish(output)?;
                published += 1;
                Ok(())
            },
        );
        return match result {
            Err(_) if refused.is_some() => Ok((published, refused)),
            result => result.map(|()| (published, None)),
        };
    }
    let mut rest = members;
    while !rest.is_empty() {
        // Each batch is published whole before the next is admitted.
        let room = Room::new(room.capacity, room.running);
        let len = rest
            .iter()
            .take(window)
            .enumerate()
            .take_while(|&(index, &(member, cost))| room.admit(cost, hint(member), index == 0))
            .count();
        let (batch, tail) = rest.split_at(len);
        rest = tail;
        let batch = batch.iter().map(|&(member, _)| member).collect();
        let (outputs, failure) = crate::parallel::map_prefix(batch, decode);
        for output in outputs {
            let Some(output) = output else {
                return Ok((published, Some(len > 1)));
            };
            publish(output)?;
            published += 1;
        }
        if let Some(error) = failure {
            return Err(error);
        }
    }
    Ok((published, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Allowance;
    use crate::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn inline_members_split_runs_and_keep_archive_order() {
        let mut log = Vec::new();
        run(
            [1u32, 2, 30, 4, 50, 60, 7],
            &mut log,
            |n| {
                if n >= 10 {
                    Plan::Inline
                } else {
                    Plan::Batch(1)
                }
            },
            |log, run| {
                log.push(format!(
                    "batch {:?}",
                    run.iter().map(|m| m.0).collect::<Vec<_>>()
                ));
                Ok(run.len())
            },
            |log, n| {
                log.push(format!("inline {n}"));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            log,
            [
                "batch [1, 2]",
                "inline 30",
                "batch [4]",
                "inline 50",
                "inline 60",
                "batch [7]",
            ]
        );
    }

    #[test]
    fn a_member_a_batch_hands_back_goes_inline_and_the_rest_batch_again() {
        let mut log = Vec::new();
        run(
            [1u32, 2, 3, 4],
            &mut log,
            |_| Plan::Batch(1),
            |log, run| {
                let run = run.iter().map(|m| m.0).collect::<Vec<_>>();
                log.push(format!("batch {run:?}"));
                // The first batch publishes one member and hands back the next.
                Ok(if run[0] == 1 { 1 } else { run.len() })
            },
            |log, n| {
                log.push(format!("inline {n}"));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(log, ["batch [1, 2, 3, 4]", "inline 2", "batch [3, 4]"]);
    }

    #[test]
    fn an_inline_failure_stops_later_members() {
        let mut seen = Vec::new();
        let error = run(
            [1u32, 20, 3],
            &mut seen,
            |n| {
                if n >= 10 {
                    Plan::Inline
                } else {
                    Plan::Batch(0)
                }
            },
            |seen, run| {
                seen.extend(run.iter().map(|m| m.0));
                Ok(run.len())
            },
            |_, _| Err(Error::Cancelled),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled));
        assert_eq!(seen, [1]);
    }

    #[test]
    fn running_workspace_is_a_quarter_of_memory_up_to_a_gibibyte() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(scaled_running_workspace(None), 1024 * MIB);
        assert_eq!(scaled_running_workspace(Some(64 * 1024 * MIB)), 1024 * MIB);
        assert_eq!(scaled_running_workspace(Some(4096 * MIB)), 1024 * MIB);
        // A 512 MiB container, as SABnzbd often runs in.
        assert_eq!(scaled_running_workspace(Some(512 * MIB)), 128 * MIB);
        assert_eq!(scaled_running_workspace(Some(0)), 0);
    }

    #[test]
    fn room_admits_what_fits_and_always_one_member_alone() {
        let admitted = |costs: &[u64]| {
            let room = Room::new(10, u64::MAX);
            costs
                .iter()
                .enumerate()
                .take_while(|&(index, &cost)| room.admit(cost, 0, index == 0))
                .count()
        };
        assert_eq!(admitted(&[6, 4, 1]), 2);
        assert_eq!(admitted(&[6, 5]), 1);
        // One member over the budget still runs, alone.
        assert_eq!(admitted(&[20, 1]), 1);
        // Exactly full is full.
        assert_eq!(admitted(&[10, 1]), 1);
        assert_eq!(admitted(&[4, 6, 1]), 2);

        // The running members' workspace is free once each finishes.
        let room = Room::new(u64::MAX, 10);
        assert!(room.admit(0, 6, true));
        assert!(!room.admit(0, 5, false));
        room.finished(0, 6, true);
        assert!(room.admit(0, 5, false));

        // A retained result holds its cost until it is published.
        let room = Room::new(10, u64::MAX);
        assert!(room.admit(8, 0, true));
        room.finished(8, 0, true);
        assert!(!room.admit(4, 0, false));
        room.published(8, true);
        assert!(room.admit(4, 0, false));
    }

    #[test]
    fn a_hint_above_a_limited_workspace_runs_alone_with_all_of_it() {
        let ledger = Allowance::limited(1 << 20);
        let members = [(0usize, 0), (1, 0), (2, 0)];
        let mut published = Vec::new();
        let count = ledger
            .batches(
                &members,
                u64::MAX,
                true,
                &mut published,
                |index| if index == 1 { u64::MAX } else { 16 },
                || Ok(()),
                |index, ledger| {
                    let len = if index == 1 { 900 << 10 } else { 16 };
                    Ok(Buffer::filled(len, 0u8, ledger)?)
                },
                |published, data| {
                    published.push(data.len());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(published, [16, 900 << 10, 16]);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn a_refusal_leaves_the_member_and_those_after_it_to_the_caller() {
        let ledger = Allowance::limited(1 << 20);
        let members = [(0usize, 0), (1, 0), (2, 0)];
        let finished = AtomicUsize::new(0);
        let mut seen = Vec::new();
        let count = ledger
            .batches(
                &members,
                u64::MAX,
                true,
                &mut seen,
                |_| 16,
                || Ok(()),
                |index, ledger| {
                    if index < 2 {
                        let data = Buffer::filled(16, 0u8, ledger)?;
                        finished.fetch_add(1, Ordering::SeqCst);
                        return Ok((index, data));
                    }
                    // Refused only once the others are done, so none is skipped.
                    while finished.load(Ordering::SeqCst) < 2 {
                        std::hint::spin_loop();
                    }
                    // Larger than the whole workspace, so refused however the
                    // members run side by side.
                    Ok((index, Buffer::filled(2 << 20, 0u8, ledger)?))
                },
                |seen, (index, _)| {
                    seen.push(index);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(seen, [0, 1]);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn a_member_refused_beside_others_runs_again_alone() {
        let ledger = Allowance::limited(1 << 20);
        let refused_once = std::sync::atomic::AtomicBool::new(false);
        let mut published = Vec::new();
        let count = ledger
            .batches(
                &[(0u32, 0), (1, 0)],
                u64::MAX,
                true,
                &mut published,
                |_| 16,
                || Ok(()),
                |member, ledger| {
                    if member == 1 && !refused_once.swap(true, Ordering::SeqCst) {
                        // As if the member beside it had taken the room.
                        Buffer::filled(2 << 20, 0u8, ledger)?;
                    }
                    Ok(member)
                },
                |published, member| {
                    published.push(member);
                    Ok(())
                },
            )
            .unwrap();
        // One worker runs one member at a time, so it was refused alone.
        let side_by_side = crate::parallel::default_window() > 1;
        assert_eq!(count, if side_by_side { 2 } else { 1 });
        assert_eq!(published, if side_by_side { vec![0, 1] } else { vec![0] });
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn an_underestimated_hint_is_refused_without_publishing() {
        let ledger = Allowance::limited(8192);
        let count = ledger
            .batches(
                &[(0u32, 0), (1, 0)],
                u64::MAX,
                true,
                &mut (),
                |_| 1,
                || Ok(()),
                |_, ledger| Ok(Buffer::filled(16384, 0u8, ledger)?),
                |_, _| panic!("a refused result was published"),
            )
            .unwrap();
        assert_eq!(count, 0, "the refused member is left to the caller");
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn decode_and_publish_failures_release_what_the_workers_hold() {
        for publish_fails in [false, true] {
            let ledger = Allowance::limited(8192);
            let members: Vec<_> = (0..100u32).map(|index| (index, 0)).collect();
            let mut published = 0;
            let error = ledger
                .batches(
                    &members,
                    u64::MAX,
                    true,
                    &mut published,
                    |_| 256,
                    || Ok(()),
                    |_, ledger| {
                        let data = Buffer::filled(256, 0u8, ledger)?;
                        if publish_fails {
                            Ok(data)
                        } else {
                            Err(Error::Cancelled)
                        }
                    },
                    |published, _| {
                        *published += 1;
                        Err(Error::Cancelled)
                    },
                )
                .unwrap_err();
            assert_eq!(error, Error::Cancelled);
            assert_eq!(published, usize::from(publish_fails));
            assert_eq!(ledger.used(), 0);
        }
    }

    #[test]
    fn windows_publish_the_prefix_ahead_of_a_failure() {
        let members = [(0u32, 0), (1, 0), (2, 0)];
        let mut published = Vec::new();
        let error = Allowance::default()
            .batches(
                &members,
                10,
                true,
                &mut published,
                |_| 0,
                || Ok(()),
                |member, _| {
                    if member == 1 {
                        Err(Error::Cancelled)
                    } else {
                        Ok(member)
                    }
                },
                |published, member| {
                    published.push(member);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(matches!(error, Error::Cancelled));
        assert_eq!(published, [0]);
    }
}
