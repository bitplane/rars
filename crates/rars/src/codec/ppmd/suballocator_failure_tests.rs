use super::*;
use crate::codec::workspace::RefusingBudget;

#[derive(Clone, Copy, Debug)]
enum Operation {
    Glue,
    Split,
    Rare,
    Emit,
}

fn setup<B: Budget>(budget: &B, operation: Operation) -> Suballocator<B> {
    let mut allocator = Suballocator::with_allowance(budget);
    allocator.reset(512 * ALLOC_UNIT_BYTES);
    match operation {
        Operation::Glue => {
            for offset in [16, 17, 24, 25] {
                allocator.try_free(offset, 1).unwrap();
            }
        }
        Operation::Rare => {
            allocator.lo_bump = allocator.hi_bump;
            allocator.glue_count = 1;
            allocator.try_free(16, 12).unwrap();
        }
        _ => {}
    }
    allocator
}

fn run<B: Budget>(allocator: &mut Suballocator<B>, operation: Operation) -> Result<Option<u32>> {
    match operation {
        Operation::Glue => allocator.glue_inner().map(|_| None),
        Operation::Split => allocator.try_split_in_place(16, 12, 3).map(|_| None),
        Operation::Rare => allocator.try_alloc(3, AllocSide::Lo, 0),
        Operation::Emit => allocator.emit_run(16, 300).map(|_| None),
    }
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    lists: Vec<Vec<u32>>,
    lo: u32,
    hi: u32,
    start: u32,
    text_capacity: usize,
    glue_count: u32,
}
fn snapshot<B: Budget>(allocator: &Suballocator<B>) -> Snapshot {
    Snapshot {
        lists: allocator
            .free_lists
            .iter()
            .map(|list| list.to_vec())
            .collect(),
        lo: allocator.lo_bump,
        hi: allocator.hi_bump,
        start: allocator.units_start,
        text_capacity: allocator.text_capacity_bytes,
        glue_count: allocator.glue_count,
    }
}

fn check_refusals(operation: Operation) {
    let baseline = RefusingBudget::new(usize::MAX);
    let mut allocator = setup(&baseline, operation);
    let first = baseline.attempts();
    let result = run(&mut allocator, operation).unwrap();
    let last = baseline.attempts();
    let completed = snapshot(&allocator);
    assert!(last > first);
    drop(allocator);
    assert_eq!(baseline.used(), 0);
    for failure in first..last {
        let budget = RefusingBudget::new(failure);
        let mut allocator = setup(&budget, operation);
        let before = snapshot(&allocator);
        assert_eq!(run(&mut allocator, operation), Err(Error::Cancelled));
        assert_eq!(
            snapshot(&allocator),
            before,
            "{operation:?}, refusal={failure}"
        );
        assert_eq!(run(&mut allocator, operation).unwrap(), result);
        assert_eq!(snapshot(&allocator), completed);
        drop(allocator);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn glue_refusals_preserve_free_blocks_and_retry_order() {
    check_refusals(Operation::Glue);
}
#[test]
fn split_refusals_preserve_the_whole_source_block() {
    check_refusals(Operation::Split);
}
#[test]
fn rare_allocation_refusals_do_not_lose_the_popped_block() {
    check_refusals(Operation::Rare);
}
#[test]
fn run_emission_refusals_do_not_publish_partial_runs() {
    check_refusals(Operation::Emit);
}

#[test]
fn cancelled_glue_preserves_original_free_lists() {
    let mut succeeded = false;
    for checks in 0..128 {
        let mut allocator = setup(&Allowance::default(), Operation::Glue);
        let before = snapshot(&allocator);
        let token = crate::ReadCancellation::new();
        allocator.read_control = crate::read_control::ReadControl::new(Some(&token));
        allocator.read_control.cancel_after_checks(checks);
        match allocator.glue_inner() {
            Err(Error::Cancelled) => assert_eq!(snapshot(&allocator), before, "checks={checks}"),
            Ok(()) => {
                succeeded = true;
                break;
            }
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }
    assert!(succeeded);
}

#[derive(Clone, Copy, Debug)]
enum ModelOperation {
    Push,
    GrowBump,
    GrowSplit,
    GrowGlue,
    ShrinkSwap,
    ShrinkSplit,
}

fn context(num_stats: u16, array_offset: u32) -> Context {
    Context {
        stats: Stats::One(State {
            symbol: 0,
            freq: 1,
            successor: Successor::None,
        }),
        num_stats,
        summ_freq: 0,
        suffix: None,
        _header_offset: 500,
        array_offset,
    }
}

// These helpers only manipulate simulated offsets; no state arena is needed.
fn model_setup<B: Budget>(budget: &B, operation: ModelOperation) -> PpmdState<B> {
    let mut model = PpmdState::with_allowance(budget);
    model.max_contexts = 100;
    model.suballoc.reset(1024 * ALLOC_UNIT_BYTES);
    match operation {
        ModelOperation::Push => return model,
        ModelOperation::GrowBump => {}
        ModelOperation::GrowSplit => {
            model.suballoc.lo_bump = model.suballoc.hi_bump;
            model.suballoc.glue_count = 1;
            // A split tail and the released array both need bucket 0.
            for offset in [16, 24, 32] {
                model.suballoc.try_free(offset, 1).unwrap();
            }
            model.suballoc.try_free(100, 3).unwrap();
        }
        ModelOperation::GrowGlue => {
            model.suballoc.lo_bump = model.suballoc.hi_bump;
            // Glue fills the initially reserved four-entry release bucket.
            for offset in [16, 17, 24, 25, 32, 33, 40, 41] {
                model.suballoc.try_free(offset, 1).unwrap();
            }
            model.suballoc.try_free(100, 4).unwrap();
        }
        ModelOperation::ShrinkSwap => model.suballoc.try_free(100, 2).unwrap(),
        ModelOperation::ShrinkSplit => {}
    }
    let count = match operation {
        ModelOperation::GrowBump | ModelOperation::GrowSplit => 2,
        ModelOperation::GrowGlue => 4,
        _ => 24,
    };
    model.contexts.try_push(context(count, 600)).unwrap();
    model
}

fn model_run<B: Budget>(model: &mut PpmdState<B>, operation: ModelOperation) -> Result<()> {
    match operation {
        ModelOperation::Push => {
            assert_eq!(
                model.push_context(
                    State {
                        symbol: 0,
                        freq: 1,
                        successor: Successor::None
                    },
                    None
                )?,
                Some(0)
            );
        }
        ModelOperation::GrowBump | ModelOperation::GrowSplit => {
            assert!(model.grow_state_array(0, 3)?);
        }
        ModelOperation::GrowGlue => {
            assert!(model.grow_state_array(0, 5)?);
        }
        ModelOperation::ShrinkSwap => model.shrink_state_array(0, 24, 4)?,
        ModelOperation::ShrinkSplit => model.shrink_state_array(0, 24, 6)?,
    }
    Ok(())
}

#[test]
fn model_helper_refusals_keep_contexts_and_blocks_owned() {
    for operation in [
        ModelOperation::Push,
        ModelOperation::GrowBump,
        ModelOperation::GrowSplit,
        ModelOperation::GrowGlue,
        ModelOperation::ShrinkSwap,
        ModelOperation::ShrinkSplit,
    ] {
        let budget = RefusingBudget::new(usize::MAX);
        let mut model = model_setup(&budget, operation);
        let start = budget.attempts();
        model_run(&mut model, operation).unwrap();
        let end = budget.attempts();
        assert!(end > start);
        let completed = snapshot(&model.suballoc);
        let completed_contexts = format!("{:?}", &*model.contexts);
        drop(model);
        assert_eq!(budget.used(), 0);
        for fail_at in start..end {
            let budget = RefusingBudget::new(fail_at);
            let mut model = model_setup(&budget, operation);
            let before = snapshot(&model.suballoc);
            let contexts = format!("{:?}", &*model.contexts);
            let checkpoint = if matches!(operation, ModelOperation::GrowGlue) {
                let mut reference = model_setup(&Allowance::default(), operation);
                reference.suballoc.glue_inner().unwrap();
                reference.suballoc.glue_count = GLUE_RESET;
                Some(snapshot(&reference.suballoc))
            } else {
                None
            };
            assert_eq!(
                model_run(&mut model, operation),
                Err(Error::Cancelled),
                "{operation:?}, {fail_at}"
            );
            assert_eq!(format!("{:?}", &*model.contexts), contexts);
            let actual = snapshot(&model.suballoc);
            assert!(
                actual == before || Some(&actual) == checkpoint.as_ref(),
                "{operation:?}, {fail_at}: {actual:?}"
            );
            model_run(&mut model, operation).unwrap();
            assert_eq!(snapshot(&model.suballoc), completed);
            assert_eq!(format!("{:?}", &*model.contexts), completed_contexts);
            drop(model);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn growth_renews_release_capacity_consumed_by_glue() {
    let baseline = RefusingBudget::new(usize::MAX);
    let mut model = model_setup(&baseline, ModelOperation::GrowGlue);
    model.suballoc.reserve_release(Some(1)).unwrap();
    model.suballoc.glue_inner().unwrap();
    assert_eq!(model.suballoc.free_lists[1].len(), 4);
    assert_eq!(model.suballoc.free_lists[1].capacity(), 4);
    let renewal = baseline.attempts();
    model.suballoc.reserve_release(Some(1)).unwrap();
    assert!(baseline.attempts() > renewal);
    drop(model);
    assert_eq!(baseline.used(), 0);

    let budget = RefusingBudget::new(renewal);
    let mut model = model_setup(&budget, ModelOperation::GrowGlue);
    assert_eq!(model.grow_state_array(0, 5), Err(Error::Cancelled));
    assert_eq!(model.contexts[0].array_offset, 600);
    assert_eq!(model.suballoc.glue_count, GLUE_RESET);
    assert_eq!(&*model.suballoc.free_lists[1], &[16, 24, 32, 40]);
    assert_eq!(&*model.suballoc.free_lists[3], &[100]);
    assert!(model.grow_state_array(0, 5).unwrap());
    assert_eq!(model.contexts[0].array_offset, 100);
    assert_eq!(&*model.suballoc.free_lists[1], &[16, 24, 32, 40, 600]);
    drop(model);
    assert_eq!(budget.used(), 0);
}

#[test]
fn real_workspace_refusals_preserve_split_and_glue_sources() {
    for operation in [
        Operation::Glue,
        Operation::Split,
        Operation::Rare,
        Operation::Emit,
    ] {
        let limit = 4096;
        let budget = Allowance::limited(limit);
        let mut allocator = setup(&budget, operation);
        // Glue's two scratch arrays fit; destination admission does not.
        // Other operations can admit one destination before a later refusal.
        let headroom = if matches!(operation, Operation::Glue) {
            4 * std::mem::size_of::<(u32, u32)>() + 8 * std::mem::size_of::<Option<(u32, u32)>>()
        } else {
            16
        };
        let filler =
            Buffer::<u8, _>::with_capacity((limit - budget.used()) as usize - headroom, &budget)
                .unwrap();
        let before = snapshot(&allocator);
        let Err(Error::WorkspaceLimitExceeded(details)) = run(&mut allocator, operation) else {
            panic!("expected workspace refusal: {operation:?}");
        };
        if matches!(operation, Operation::Glue) {
            // Both scratch charges are still live when destination growth is
            // refused. A scratch-allocation failure has different diagnostics.
            assert_eq!(details.used, limit);
            assert_eq!(details.required, 4 * std::mem::size_of::<u32>() as u64);
        }
        assert_eq!(snapshot(&allocator), before);
        drop(filler);
        run(&mut allocator, operation).unwrap();
        drop(allocator);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn late_glue_cancellation_keeps_all_free_lists() {
    let mut reached_success = false;
    for checks in 0..128 {
        let mut allocator = Suballocator::default();
        for offset in 0..5000 {
            allocator.try_free(offset * 3, 1).unwrap();
        }
        let before = snapshot(&allocator);
        let token = crate::ReadCancellation::new();
        allocator.read_control = crate::read_control::ReadControl::new(Some(&token));
        allocator.read_control.cancel_after_checks(checks);
        match allocator.glue_inner() {
            Err(Error::Cancelled) => assert_eq!(snapshot(&allocator), before, "checks={checks}"),
            Ok(()) => {
                reached_success = true;
                break;
            }
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }
    assert!(reached_success);
}

// Pre-change glue behavior, using an independent map and explicit emission.
fn reference_glue(lists: &[Vec<u32>]) -> Vec<Vec<u32>> {
    use std::collections::HashMap;
    let mut threaded = Vec::new();
    for (bucket, list) in lists.iter().enumerate().rev() {
        for &offset in list {
            threaded.push((
                offset,
                Suballocator::<Allowance>::bucket_units(bucket) as u32,
            ));
        }
    }
    let mut sizes: HashMap<u32, u32> = threaded.iter().copied().collect();
    for &(offset, _) in &threaded {
        let mut units = sizes[&offset];
        if units == 0 {
            continue;
        }
        while let Some(&next) = sizes.get(&(offset + units)) {
            if units + next >= 0x10000 {
                break;
            }
            sizes.insert(offset + units, 0);
            units += next;
        }
        sizes.insert(offset, units);
    }
    let mut output = vec![Vec::new(); N_BUCKETS];
    for &(mut offset, _) in &threaded {
        let mut units = sizes[&offset];
        if units == 0 {
            continue;
        }
        while units > 128 {
            output[37].push(offset);
            offset += 128;
            units -= 128;
        }
        let mut bucket = Suballocator::<Allowance>::bucket_for(units as usize).unwrap();
        if Suballocator::<Allowance>::bucket_units(bucket) != units as usize {
            bucket -= 1;
            let prefix = Suballocator::<Allowance>::bucket_units(bucket) as u32;
            output[(units - prefix - 1) as usize].push(offset + prefix);
        }
        output[bucket].push(offset);
    }
    output
}

#[test]
fn glue_preserves_reference_order_at_all_bucket_and_merge_boundaries() {
    let mut allocator = Suballocator::default();
    let mut offset = 0;
    for bucket in 0..N_BUCKETS {
        let units = Suballocator::<Allowance>::bucket_units(bucket);
        for extra in 1..=128 {
            allocator.try_free(offset, units).unwrap();
            allocator.try_free(offset + units as u32, extra).unwrap();
            offset += units as u32 + 256;
        }
    }
    // Runs around the 16-bit merge cap and repeated starts exercise both
    // counting and publication, including the reference's duplicate behavior.
    for i in 0..513 {
        allocator.try_free(offset + i * 128, 128).unwrap();
    }
    offset += 70000;
    allocator.try_free(offset, 3).unwrap();
    allocator.try_free(offset, 3).unwrap();
    let expected = reference_glue(&snapshot(&allocator).lists);
    allocator.glue_inner().unwrap();
    assert_eq!(snapshot(&allocator).lists, expected);
}
