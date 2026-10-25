use super::*;

#[test]
fn repeated_shrink_and_regrow_reuses_freed_arena_storage() {
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let first = arena.alloc(7).unwrap();
    let original_len = arena.states.len();
    let mut block = first;
    for _ in 0..32 {
        arena.release_tail(block, 7, 6).unwrap();
        arena.release(block, 6).unwrap();
        block = arena.alloc(7).unwrap();
        assert_eq!(
            arena.states.len(),
            original_len,
            "all 256 previous slots were free"
        );
    }
}

fn state(symbol: u8) -> State {
    State {
        symbol,
        freq: symbol.wrapping_add(1),
        successor: Successor::Raw(u32::from(symbol) + 9),
    }
}

fn assert_state(actual: &State, expected: &State) {
    assert_eq!(actual.symbol, expected.symbol);
    assert_eq!(actual.freq, expected.freq);
    assert_eq!(actual.successor, expected.successor);
}

#[test]
fn arena_classes_splitting_and_reuse_cover_all_sizes() {
    for count in 1..=256 {
        let class = StateArena::<Allowance>::class(count);
        assert!(StateArena::<Allowance>::block_len(class) >= count);
        if class > 0 {
            assert!(StateArena::<Allowance>::block_len(class - 1) < count);
        }
    }
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let first = arena.alloc(7).unwrap();
    let second = arena.alloc(7).unwrap();
    arena.release(first, 7).unwrap();
    arena.release(second, 7).unwrap();
    assert_eq!(arena.alloc(0).unwrap(), second);
    let mut occupied = vec![false; arena.states.len()];
    occupied[second as usize..second as usize + 2].fill(true);
    for (class, list) in arena.free.iter().enumerate() {
        for &at in list {
            for slot in
                &mut occupied[at as usize..at as usize + StateArena::<Allowance>::block_len(class)]
            {
                assert!(!*slot, "overlapping split blocks");
                *slot = true;
            }
        }
    }
    assert!(occupied.into_iter().all(|v| v));
    assert_eq!(arena.free_slots, 510);
    let len = arena.states.len();
    for class in 0..7 {
        arena.alloc(class).unwrap();
    }
    assert_eq!(arena.states.len(), len);
    assert_eq!(arena.free_slots, 256);
}

#[test]
fn coalescing_handles_unaligned_mixed_blocks_and_preserves_live_states() {
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let live = arena.alloc(0).unwrap();
    arena.states[live as usize] = state(77);
    let small = arena.alloc(0).unwrap();
    let medium = arena.alloc(1).unwrap();
    let large = arena.alloc(2).unwrap();
    let tail = arena.alloc(0).unwrap();
    // The free run [2,16) is unaligned and spans three size classes.
    arena.release(small, 0).unwrap();
    arena.release(medium, 1).unwrap();
    arena.release(large, 2).unwrap();
    arena.coalesce().unwrap();
    assert_eq!(arena.free_slots, 14);
    assert_eq!(&*arena.free[2], &[2]);
    assert_eq!(&*arena.free[1], &[10]);
    assert_eq!(&*arena.free[0], &[14]);
    assert_eq!(tail, 16);
    assert_state(&arena.states[live as usize], &state(77));
    assert_eq!(arena.alloc(2).unwrap(), 2);
    assert_eq!(arena.free_slots, 6);
}

#[test]
fn state_growth_shrink_cycles_preserve_values_and_stop_growing_storage() {
    let mut model = PpmdState::with_allowance(&Allowance::default());
    model
        .contexts
        .try_push(Context {
            stats: Stats::One(state(0)),
            num_stats: 1,
            summ_freq: 0,
            suffix: None,
            _header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap();
    let mut high_water = 0;
    for cycle in 0..64 {
        for count in 2..=256 {
            model.push_state(0, state((count - 1) as u8)).unwrap();
            for (i, actual) in model.states(0).iter().enumerate() {
                assert_state(actual, &state(i as u8));
            }
        }
        assert!(matches!(
            model.push_state(0, state(0)),
            Err(Error::InvalidData("RAR PPMd context has too many states"))
        ));
        for count in (1..256).rev() {
            model.truncate_states(0, count).unwrap();
            assert_eq!(model.states(0).len(), count);
            for (i, actual) in model.states(0).iter().enumerate() {
                assert_state(actual, &state(i as u8));
            }
        }
        model.truncate_states(0, 1).unwrap();
        assert!(matches!(model.contexts[0].stats, Stats::One(_)));
        // A live 128-slot source can split the free space while it grows
        // to 256 slots. Allow that one extra destination block, then demand
        // a stable bound rather than growth proportional to the cycles.
        assert!(model.arena.states.len() <= 3 * 256);
        if cycle == 2 {
            high_water = model.arena.states.len();
        } else if cycle > 2 {
            assert_eq!(model.arena.states.len(), high_water);
        }
    }
}

#[test]
fn arena_checkpoint_and_reset_preserve_independence_and_reuse_storage() {
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let at = arena.alloc(7).unwrap();
    arena.states[at as usize] = state(3);
    arena.release_tail(at, 7, 0).unwrap();
    let mut copy = arena.try_clone().unwrap();
    copy.states[at as usize] = state(8);
    copy.alloc(0).unwrap();
    assert_state(&arena.states[at as usize], &state(3));
    assert_eq!(arena.free_slots, 254);
    assert_eq!(copy.free_slots, 252);
    let capacity = arena.states.capacity();
    let pointer = arena.states.as_ptr();
    arena.reset();
    assert_eq!(arena.free_slots, 0);
    assert!(arena.free.iter().all(|list| list.is_empty()));
    assert_eq!(arena.alloc(7).unwrap(), 0);
    assert_eq!(arena.states.capacity(), capacity);
    assert_eq!(arena.states.as_ptr(), pointer);
}

#[test]
fn every_coalescing_pass_waits_for_enough_genuine_frees() {
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let block = arena.alloc(7).unwrap();
    arena.release_tail(block, 7, 6).unwrap();
    arena.release(block, 6).unwrap();
    assert_eq!(arena.released_since_coalesce, 256);
    let whole = arena.alloc(7).unwrap();
    assert_eq!(arena.released_since_coalesce, 0);
    // Fragment the same region into tiny blocks, then mark a completed scan.
    arena.release(whole, 7).unwrap();
    let tiny = arena.alloc(0).unwrap();
    assert_eq!(
        arena.released_since_coalesce, 256,
        "splitting must not count old free storage again"
    );
    arena.coalesce().unwrap();
    assert_eq!(arena.released_since_coalesce, 0);
    arena.release(tiny, 0).unwrap();
    let old_len = arena.states.len();
    arena.alloc(7).unwrap();
    assert_eq!(
        arena.released_since_coalesce, 2,
        "successful scans must also be amortized"
    );
    assert_eq!(arena.states.len(), old_len + 256);
}

#[test]
fn coalescing_cancellation_preserves_free_block_ownership_at_every_checkpoint() {
    let mut completed = false;
    for checks in 0..32 {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        let mut arena = StateArena::with_allowance(&Allowance::default());
        let at = arena.alloc(7).unwrap();
        arena.release_tail(at, 7, 0).unwrap();
        let before: Vec<_> = arena.free.iter().map(|list| list.to_vec()).collect();
        arena.read_control = control.clone();
        control.cancel_after_checks(checks);
        match arena.coalesce() {
            Err(Error::Cancelled) => {
                assert_eq!(
                    arena
                        .free
                        .iter()
                        .map(|list| list.to_vec())
                        .collect::<Vec<_>>(),
                    before
                );
                assert_eq!(arena.free_slots, 254);
            }
            Ok(()) => {
                completed = true;
                break;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert!(completed);
}

#[test]
fn arena_allocation_refusals_release_scratch_and_checkpoint_charges() {
    refuse_each_allocation(|budget| {
        let mut arena = StateArena::with_allowance(budget);
        let at = arena.alloc(7)?;
        arena.release_tail(at, 7, 0)?;
        arena.release(at, 0)?;
        let before: Vec<_> = arena.free.iter().map(|list| list.to_vec()).collect();
        let slots = arena.free_slots;
        if let Err(error) = arena.coalesce() {
            assert_eq!(
                arena
                    .free
                    .iter()
                    .map(|list| list.to_vec())
                    .collect::<Vec<_>>(),
                before
            );
            assert_eq!(arena.free_slots, slots);
            return Err(error);
        }
        let copy = arena.try_clone()?;
        assert_eq!(copy.free_slots, 256);
        arena.alloc(7)?;
        assert_eq!(arena.states.len(), 256);
        Ok(())
    });
}

fn refuse_each_allocation(
    mut run: impl FnMut(&crate::codec::workspace::RefusingBudget) -> Result<()>,
) {
    use crate::codec::workspace::RefusingBudget;
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    assert_eq!(baseline.used(), 0);
    for index in 0..baseline.attempts() {
        let budget = RefusingBudget::new(index);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation {index}"
        );
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn varied_arena_recycling_preserves_all_live_ranges() {
    let mut arena = StateArena::with_allowance(&Allowance::default());
    let mut live: Vec<(u32, usize, u8)> = Vec::new();
    let mut rng = 0x1234_5678u32;
    for step in 0..4000 {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        if !live.is_empty() && (live.len() >= 80 || rng & 3 == 0) {
            let (at, class, value) = live.swap_remove(rng as usize % live.len());
            let len = StateArena::<Allowance>::block_len(class);
            for actual in &arena.states[at as usize..at as usize + len] {
                assert_state(actual, &state(value));
            }
            arena.release(at, class).unwrap();
        } else {
            let class = (rng >> 8) as usize % ARENA_CLASSES;
            let at = arena.alloc(class).unwrap();
            let len = StateArena::<Allowance>::block_len(class);
            for &(other, other_class, _) in &live {
                let other_len = StateArena::<Allowance>::block_len(other_class);
                assert!(
                    at as usize + len <= other as usize
                        || at as usize >= other as usize + other_len
                );
            }
            arena.states[at as usize..at as usize + len].fill(state(step as u8));
            live.push((at, class, step as u8));
        }
        if step % 17 == 0 {
            arena.coalesce().unwrap();
        }
        let occupied: usize = live
            .iter()
            .map(|&(_, class, _)| StateArena::<Allowance>::block_len(class))
            .sum();
        assert_eq!(occupied + arena.free_slots, arena.states.len());
    }
    for (at, class, value) in live {
        for actual in
            &arena.states[at as usize..at as usize + StateArena::<Allowance>::block_len(class)]
        {
            assert_state(actual, &state(value));
        }
    }
}

#[test]
fn maintenance_refusal_can_use_already_admitted_arena_capacity() {
    let capacity = 65536;
    let budget = Allowance::limited(
        (capacity * std::mem::size_of::<State>() + 4 * std::mem::size_of::<u32>()) as u64,
    );
    let mut arena = StateArena::with_allowance(&budget);
    arena.states = Buffer::with_capacity(capacity, &budget).unwrap();
    arena.states.resize(60000, State::EMPTY).unwrap();
    arena.release(0, 6).unwrap();
    arena.release(128, 6).unwrap();
    for _ in 0..64 {
        let at = arena.alloc(6).unwrap();
        arena.release(at, 6).unwrap();
    }
    assert!(arena.released_since_coalesce >= arena.states.len() / 8);
    assert_eq!(arena.alloc(7).unwrap(), 60000);
    assert_eq!(
        arena.released_since_coalesce, 0,
        "the quota-refused scan was attempted"
    );
    assert_eq!(arena.free_slots, 256);
    assert_eq!(arena.states.capacity(), capacity);
}
