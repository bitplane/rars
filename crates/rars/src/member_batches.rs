//! The parallel extraction driver shared by every format that has one.
//!
//! Members are handled in archive order. A member a worker can decode alone
//! and cheaply joins a batch. Any other member (split, too large to buffer)
//! is decoded inline on the calling thread, after the batches before it have
//! been published. One large member therefore no longer serializes the whole
//! archive, and inline members leave the worker pool idle for any parallelism
//! inside their own decode.

use crate::Result;

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
/// caller's writer factory.
pub(crate) fn run<T: Copy, C: ?Sized>(
    items: impl IntoIterator<Item = T>,
    ctx: &mut C,
    mut plan: impl FnMut(T) -> Plan,
    mut batches: impl FnMut(&mut C, &[(T, u64)]) -> Result<()>,
    mut inline: impl FnMut(&mut C, T) -> Result<()>,
) -> Result<()> {
    let mut pending = Vec::new();
    for item in items {
        match plan(item) {
            Plan::Batch(cost) => pending.push((item, cost)),
            Plan::Inline => {
                if !pending.is_empty() {
                    batches(ctx, &pending)?;
                    pending.clear();
                }
                inline(ctx, item)?;
            }
        }
    }
    if !pending.is_empty() {
        batches(ctx, &pending)?;
    }
    Ok(())
}

/// Decodes `members` on workers, at most one per worker and `capacity` bytes of
/// cost per batch, and publishes each batch in order before starting the next.
/// A member costing more than `capacity` forms a batch of its own. The members
/// ahead of a failure in its batch are published before the failure returns.
pub(crate) fn in_windows<T: Copy + Send, O: Send, C: ?Sized>(
    members: &[(T, u64)],
    capacity: u64,
    ctx: &mut C,
    check: impl Fn() -> Result<()>,
    decode: impl Fn(T) -> Result<O> + Sync + Send,
    mut publish: impl FnMut(&mut C, O) -> Result<()>,
) -> Result<()> {
    let window = crate::parallel::default_window().max(1);
    let mut rest = members;
    while !rest.is_empty() {
        check()?;
        let (batch, tail) = rest.split_at(batch_len(rest, window, capacity));
        rest = tail;
        let batch = batch.iter().map(|&(member, _)| member).collect();
        let (outputs, failure) = crate::parallel::map_prefix(batch, &decode);
        for output in outputs {
            publish(ctx, output)?;
        }
        if let Some(error) = failure {
            return Err(error);
        }
    }
    Ok(())
}

/// How many of `members` the next batch takes: at least one, at most `window`,
/// and no more than `capacity` bytes of cost unless one member alone exceeds it.
fn batch_len<T>(members: &[(T, u64)], window: usize, capacity: u64) -> usize {
    let mut used = 0u64;
    let mut len = 0;
    while len < members.len().min(window) {
        let cost = members[len].1;
        if len != 0 && used.saturating_add(cost) > capacity {
            break;
        }
        used = used.saturating_add(cost);
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

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
                Ok(())
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
                Ok(())
            },
            |_, _| Err(Error::Cancelled),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled));
        assert_eq!(seen, [1]);
    }

    #[test]
    fn batches_respect_the_window_and_byte_budget() {
        let costs = |costs: &[u64]| costs.iter().map(|&cost| ((), cost)).collect::<Vec<_>>();
        assert_eq!(batch_len(&costs(&[6, 4, 1]), 8, 10), 2);
        assert_eq!(batch_len(&costs(&[6, 5]), 8, 10), 1);
        // One member over the budget still runs, alone.
        assert_eq!(batch_len(&costs(&[20, 1]), 8, 10), 1);
        assert_eq!(batch_len(&costs(&[0; 20]), 8, 10), 8);
        assert_eq!(batch_len(&costs(&[1, 1]), 1, 10), 1);
        // Exactly full is full.
        assert_eq!(batch_len(&costs(&[10, 1]), 8, 10), 1);
        assert_eq!(batch_len(&costs(&[4, 6, 1]), 8, 10), 2);
    }

    #[test]
    fn windows_publish_the_prefix_ahead_of_a_failure() {
        let members = [(0u32, 0), (1, 0), (2, 0)];
        let mut published = Vec::new();
        let error = in_windows(
            &members,
            10,
            &mut published,
            || Ok(()),
            |member| {
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
