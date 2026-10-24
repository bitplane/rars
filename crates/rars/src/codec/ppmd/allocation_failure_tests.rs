use super::*;
use crate::codec::workspace::RefusingBudget;

fn state(symbol: u8) -> State {
    State {
        symbol,
        freq: 1,
        successor: Successor::Raw(u32::from(symbol)),
    }
}

fn add_context<B: Budget>(model: &mut PpmdState<B>, class: usize) {
    let at = model.arena.alloc(class).unwrap();
    let len = StateArena::<B>::block_len(class);
    for (i, slot) in model.arena.states[at as usize..at as usize + len]
        .iter_mut()
        .enumerate()
    {
        *slot = state(i as u8);
    }
    model
        .contexts
        .try_push(Context {
            stats: Stats::Many(at),
            num_stats: len as u16,
            summ_freq: len as u16,
            suffix: None,
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap();
}

// Every arena slot belongs to exactly one live block or one free block.
fn assert_partition<B: Budget>(model: &PpmdState<B>, extra_live: &[(u32, usize)]) {
    let mut occupied = vec![false; model.arena.states.len()];
    let mut mark = |at: u32, class: usize| {
        let end = at as usize + StateArena::<B>::block_len(class);
        for used in &mut occupied[at as usize..end] {
            assert!(!*used, "overlapping live/free blocks");
            *used = true;
        }
    };
    for context in &model.contexts {
        if let Stats::Many(at) = context.stats {
            mark(at, StateArena::<B>::class(context.num_stats as usize));
        }
    }
    for &(at, class) in extra_live {
        mark(at, class);
    }
    let mut free = 0;
    for (class, list) in model.arena.free.iter().enumerate() {
        for &at in list {
            mark(at, class);
            free += StateArena::<B>::block_len(class);
        }
    }
    assert_eq!(free, model.arena.free_slots);
    assert!(occupied.into_iter().all(|used| used), "unowned arena slots");
}

fn live_snapshot<B: Budget>(model: &PpmdState<B>) -> (String, Vec<String>) {
    (
        format!("{:?}", &*model.contexts),
        (0..model.contexts.len())
            .map(|i| format!("{:?}", model.states(i)))
            .collect(),
    )
}

fn free_snapshot<B: Budget>(arena: &StateArena<B>) -> (Vec<Vec<u32>>, usize, usize) {
    (
        arena.free.iter().map(|list| list.to_vec()).collect(),
        arena.free_slots,
        arena.released_since_coalesce,
    )
}

fn split_model<B: Budget>(budget: &B, reuse: bool) -> PpmdState<B> {
    let mut model = PpmdState::with_allowance(budget);
    add_context(&mut model, 7);
    if reuse {
        model.contexts.clear();
        model.arena.release(0, 7).unwrap();
    }
    model
}

fn split<B: Budget>(model: &mut PpmdState<B>, reuse: bool, remaining: usize) -> Result<()> {
    if reuse {
        assert_eq!(model.arena.reuse(0)?, Some(0));
    } else {
        model.truncate_states(0, remaining)?;
    }
    Ok(())
}

#[test]
fn split_and_shrink_refusals_preserve_ownership_and_allow_retry() {
    for (reuse, remaining) in [(true, 2), (false, 2), (false, 1)] {
        let baseline = RefusingBudget::new(usize::MAX);
        let mut model = split_model(&baseline, reuse);
        let start = baseline.attempts();
        split(&mut model, reuse, remaining).unwrap();
        let end = baseline.attempts();
        assert!(end > start);
        drop(model);
        assert_eq!(baseline.used(), 0);
        for fail_at in start..end {
            let budget = RefusingBudget::new(fail_at);
            let mut model = split_model(&budget, reuse);
            let free = free_snapshot(&model.arena);
            let live = live_snapshot(&model);
            let states = format!("{:?}", &*model.arena.states);
            // RefusingBudget injects Cancelled once per selected grow/charge.
            assert!(matches!(
                split(&mut model, reuse, remaining),
                Err(Error::Cancelled)
            ));
            assert!(budget.attempts() > fail_at);
            assert_eq!(free_snapshot(&model.arena), free);
            assert_eq!(live_snapshot(&model), live);
            assert_eq!(format!("{:?}", &*model.arena.states), states);
            assert_partition(&model, &[]);
            split(&mut model, reuse, remaining).unwrap();
            assert_partition(&model, if reuse { &[(0, 0)] } else { &[] });
            drop(model);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn split_and_shrink_workspace_refusals_preserve_ownership() {
    for reuse in [false, true] {
        let budget = Allowance::limited(4096);
        let mut model = split_model(&budget, reuse);
        // Leave room for two destination lists, then refuse a later one.
        // A new limited u32 buffer admits at least four entries (16 bytes).
        let scratch =
            Buffer::<u8, _>::with_capacity((4096 - budget.used() - 32) as usize, &budget).unwrap();
        let free = free_snapshot(&model.arena);
        let live = live_snapshot(&model);
        assert!(matches!(
            split(&mut model, reuse, 2),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(free_snapshot(&model.arena), free);
        assert_eq!(live_snapshot(&model), live);
        assert_partition(&model, &[]);
        drop(scratch);
        split(&mut model, reuse, 2).unwrap();
        assert_partition(&model, if reuse { &[(0, 0)] } else { &[] });
        drop(model);
        assert_eq!(budget.used(), 0);
    }
}

fn growth_model<B: Budget>(budget: &B, kind: usize) -> PpmdState<B> {
    let mut model = PpmdState::with_allowance(budget);
    add_context(&mut model, if kind == 3 { 6 } else { 0 });
    match kind {
        0 => {} // Append a fresh destination.
        1 | 2 => {
            // Reuse a destination exactly, or split a larger block.
            let class = if kind == 1 { 1 } else { 7 };
            let at = model.arena.alloc(class).unwrap();
            model.arena.release(at, class).unwrap();
        }
        3 => {
            // Coalescing creates four isolated class-6 blocks, filling the
            // previously reserved old-class list, plus a class-7 destination.
            // Keep all blocks live during setup so alloc cannot recycle them.
            let mut freed = Vec::new();
            for _ in 0..4 {
                freed.push(model.arena.alloc(5).unwrap());
                freed.push(model.arena.alloc(5).unwrap());
                add_context(&mut model, 0);
            }
            for _ in 0..4 {
                freed.push(model.arena.alloc(5).unwrap());
            }
            for at in freed {
                model.arena.release(at, 5).unwrap();
            }
        }
        _ => unreachable!(),
    }
    assert_partition(&model, &[]);
    model
}

#[test]
fn context_growth_refusals_preserve_all_live_and_free_blocks() {
    for kind in 0..4 {
        let baseline = RefusingBudget::new(usize::MAX);
        let mut model = growth_model(&baseline, kind);
        let start = baseline.attempts();
        model.push_state(0, state(199)).unwrap();
        let end = baseline.attempts();
        assert!(end > start);
        assert_partition(&model, &[]);
        drop(model);
        assert_eq!(baseline.used(), 0);
        for fail_at in start..end {
            let budget = RefusingBudget::new(fail_at);
            let mut model = growth_model(&budget, kind);
            let before = live_snapshot(&model);
            assert!(
                matches!(model.push_state(0, state(199)), Err(Error::Cancelled)),
                "kind={kind}, allocation={fail_at}"
            );
            assert!(budget.attempts() > fail_at);
            assert_eq!(live_snapshot(&model), before);
            // Coalescing may reorder free lists; ownership must still partition
            // the arena even if a subsequent reservation fails.
            assert_partition(&model, &[]);
            model.push_state(0, state(199)).unwrap();
            let states = model.states(0);
            for (i, actual) in states[..states.len() - 1].iter().enumerate() {
                assert_eq!(format!("{actual:?}"), format!("{:?}", state(i as u8)));
            }
            assert_eq!(
                format!("{:?}", states.last().unwrap()),
                format!("{:?}", state(199))
            );
            assert_partition(&model, &[]);
            drop(model);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn growth_renews_a_release_reservation_filled_by_coalescing() {
    let baseline = RefusingBudget::new(usize::MAX);
    let mut model = growth_model(&baseline, 3);
    model.arena.reserve_free_entry(6).unwrap();
    model.arena.coalesce().unwrap();
    assert_eq!(model.arena.free[6].len(), 4);
    assert_eq!(model.arena.free[6].len(), model.arena.free[6].capacity());
    let renewed_at = baseline.attempts();
    model.arena.reserve_free_entry(6).unwrap();
    assert!(baseline.attempts() > renewed_at);
    drop(model);
    assert_eq!(baseline.used(), 0);

    // Refuse precisely the second reservation inside the actual growth path.
    let budget = RefusingBudget::new(renewed_at);
    let mut model = growth_model(&budget, 3);
    let before = live_snapshot(&model);
    assert!(matches!(
        model.push_state(0, state(199)),
        Err(Error::Cancelled)
    ));
    assert_eq!(model.arena.released_since_coalesce, 0);
    assert_eq!(model.arena.free[6].len(), model.arena.free[6].capacity());
    assert_eq!(live_snapshot(&model), before);
    assert_partition(&model, &[]);
    model.push_state(0, state(199)).unwrap();
    assert_partition(&model, &[]);
    drop(model);
    assert_eq!(budget.used(), 0);
}

#[test]
fn growth_uses_reserved_release_after_coalescing_workspace_refusal() {
    let limit = 1024 * 1024;
    let budget = Allowance::limited(limit);
    let mut model = growth_model(&budget, 3);
    model.arena.states.reserve_total_capacity(2048).unwrap();
    let old_len = model.arena.states.len();
    let old_capacity = model.arena.states.capacity();
    // Enough for the old-class release (four u32 entries), but not the
    // coalescing bitmap. Appending a destination needs no further capacity.
    let scratch =
        Buffer::<u8, _>::with_capacity((limit - budget.used() - 16) as usize, &budget).unwrap();
    model.push_state(0, state(199)).unwrap();
    assert_eq!(model.arena.states.len(), old_len + 256);
    assert_eq!(model.arena.states.capacity(), old_capacity);
    assert_eq!(model.arena.released_since_coalesce, 128);
    for (i, actual) in model.states(0)[..128].iter().enumerate() {
        assert_eq!(format!("{actual:?}"), format!("{:?}", state(i as u8)));
    }
    assert_eq!(model.states(0)[128].symbol, 199);
    assert_partition(&model, &[]);
    drop(scratch);
    drop(model);
    assert_eq!(budget.used(), 0);
}
