fn refuse_each_ppmd_allocation(
    mut run: impl FnMut(&crate::codec::workspace::RefusingBudget) -> Result<()>,
) {
    use crate::codec::workspace::RefusingBudget;
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    let attempts = baseline.attempts();
    assert!(attempts > 0);
    assert_eq!(baseline.used(), 0);
    for index in 0..attempts {
        let budget = RefusingBudget::new(index);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation {index}"
        );
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn reader_ppmd_workspace_refusals_release_contexts_states_text_and_checkpoints() {
    let data = b"abracadabra and evolving contexts abracadabra";
    let mut encoder = PpmdEncoder::new(4, 2, 1).unwrap();
    for &byte in data {
        encoder.encode_literal(byte).unwrap();
    }
    let (packed, _) = encoder.finish_keeping_model().unwrap();
    refuse_each_ppmd_allocation(|budget| {
        let mut model = PpmdState::with_allowance(budget);
        model.max_contexts = model_context_limit(1);
        model.suballoc.reset(1024 * 1024);
        model.init_model(4)?;
        let mut input = Bytes { input: &packed };
        model.range.init(&mut input)?;
        for &byte in data {
            assert_eq!(model.decode_symbol(&mut input)?, Some(byte));
        }
        let checkpoint = model.try_clone()?;
        assert_eq!(checkpoint.contexts.len(), model.contexts.len());
        assert_eq!(checkpoint.text, model.text);
        assert_eq!(
            checkpoint.contexts[0].states[0].freq,
            model.contexts[0].states[0].freq
        );
        Ok(())
    });
}

#[test]
fn reader_ppmd_workspace_refusals_release_free_lists_and_glue_lookup() {
    refuse_each_ppmd_allocation(|budget| {
        let mut allocator = super::Suballocator::with_allowance(budget);
        allocator.reset(32 * ALLOC_UNIT_BYTES);
        for offset in [10, 11, 20, 21] {
            allocator.try_free(offset, 1)?;
        }
        allocator.glue_inner()?;
        assert_eq!(&*allocator.free_lists[1], &[10, 20]);
        let checkpoint = allocator.try_clone()?;
        assert_eq!(checkpoint.free_lists[1], allocator.free_lists[1]);
        Ok(())
    });
}

#[test]
fn reader_ppmd_workspace_refusal_is_not_an_arena_restart() {
    let ledger = Allowance::limited(1);
    let mut model = PpmdState::with_allowance(&ledger);
    let mut input = Bytes { input: &[0; 5] };
    let mut escape = 2;
    assert!(matches!(
        model.decode_init(0x20 | 3, &mut input, &mut escape),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert!(!model.allocated);
    assert!(model.contexts.is_empty());
    assert_eq!(ledger.used(), 0);
}

#[test]
fn reader_ppmd_glue_index_probes_collisions_wraps_and_accepts_zero_offsets() {
    let keys: Vec<_> = (0..1000u32)
        .filter(|&key| GlueIndex::<Allowance>::hash(key) & 7 == 7)
        .take(3)
        .collect();
    let list: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, &key)| (key, index as u32 + 1))
        .collect();
    let ledger = Allowance::limited(1024);
    let control = crate::read_control::ReadControl::default();
    let mut index = GlueIndex::new(&list, &ledger, &control).unwrap();
    assert_eq!(index.entries.len(), 8);
    assert!(index.entries[7].is_some() && index.entries[0].is_some() && index.entries[1].is_some());
    for &(key, units) in &list {
        assert_eq!(index.get(&key), Some(&units));
    }
    index.insert(keys[1], 0);
    assert_eq!(index.get(&keys[1]), Some(&0));
    assert_eq!(index.get(&u32::MAX), None);
    drop(index);
    let zero = GlueIndex::new(&[(0, 1), (u32::MAX, 2)], &ledger, &control).unwrap();
    assert_eq!(zero.get(&0), Some(&1));
    assert_eq!(zero.get(&u32::MAX), Some(&2));
    drop(zero);
    let empty = GlueIndex::new(&[], &ledger, &control).unwrap();
    assert_eq!(empty.get(&0), None);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn reader_ppmd_glue_index_matches_map_lookup_and_duplicate_overwrites() {
    let list = [(10, 1), (4, 3), (10, 8), (20, 2), (4, 5)];
    let ledger = Allowance::limited(1024);
    let mut index =
        GlueIndex::new(&list, &ledger, &crate::read_control::ReadControl::default()).unwrap();
    let mut reference: std::collections::HashMap<_, _> = list.into_iter().collect();
    for key in [0, 4, 10, 20, 21, u32::MAX] {
        assert_eq!(index.get(&key), reference.get(&key));
    }
    for (key, value) in [(10, 0), (4, 7), (20, 0)] {
        index.insert(key, value);
        reference.insert(key, value);
        assert_eq!(index.get(&key), reference.get(&key));
    }
    assert_eq!(
        ledger.used(),
        index.entries.capacity() as u64 * std::mem::size_of::<Option<(u32, u32)>>() as u64
    );
    drop(index);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn cancellation_interrupts_suballocator_maintenance() {
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    control.cancel_after_checks(1);
    let mut allocator = Suballocator {
        read_control: control,
        ..Suballocator::default()
    };
    allocator.free_lists[0] = (0..5000).collect::<Vec<_>>().into();
    assert_eq!(allocator.glue_inner(), Err(Error::Cancelled));
    assert!(token.is_cancelled());
}
use super::*;
type PpmdDecoder = PpmdState<Allowance>;
type Suballocator = super::Suballocator<Allowance>;

#[test]
fn alloc_tables_match_spec_pattern() {
    let t = alloc_tables();
    // Spec §4.2: bucket sizes are 1,2,3,4 then groups of 4 at strides 1,2,3,4.
    // First 12 buckets cover 1..4, then 6,8,10,12, then 15,18,21,24.
    assert_eq!(t.index_to_units[0], 1);
    assert_eq!(t.index_to_units[1], 2);
    assert_eq!(t.index_to_units[2], 3);
    assert_eq!(t.index_to_units[3], 4);
    assert_eq!(t.index_to_units[4], 6);
    assert_eq!(t.index_to_units[5], 8);
    assert_eq!(t.index_to_units[6], 10);
    assert_eq!(t.index_to_units[7], 12);
    assert_eq!(t.index_to_units[8], 15);
    assert_eq!(t.index_to_units[9], 18);
    assert_eq!(t.index_to_units[10], 21);
    assert_eq!(t.index_to_units[11], 24);
    // From bucket 12 onward, stride is 4: 28, 32, 36, 40 ... up to 128.
    assert_eq!(t.index_to_units[12], 28);
    assert_eq!(t.index_to_units[N_BUCKETS - 1], 128);

    // 1-unit requests resolve to bucket 0; 2 → 1; 5,6 → 4 (the 6-unit bucket).
    assert_eq!(t.units_to_index[0], 0);
    assert_eq!(t.units_to_index[1], 1);
    assert_eq!(t.units_to_index[4], 4); // 5 units
    assert_eq!(t.units_to_index[5], 4); // 6 units (same bucket as 5)
}

#[test]
fn suballoc_alloc_until_exhaustion() {
    // Pool needs the text reservation (1/8) plus units area. 16 units
    // total gives 2-unit text region + 14 units of headroom for bumping.
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    // 14 units between lo_bump and hi_bump → can hand out 7 × 2-unit blocks.
    for _ in 0..7 {
        assert!(s.alloc(2, AllocSide::Lo, 0).is_some());
    }
    assert!(s.alloc(2, AllocSide::Lo, 0).is_none()); // pool full
}

#[test]
fn suballoc_reuses_freed_bucket() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    let offsets: Vec<u32> = (0..7)
        .map(|_| s.alloc(2, AllocSide::Lo, 0).expect("alloc"))
        .collect();
    assert!(s.alloc(2, AllocSide::Lo, 0).is_none()); // full
    s.free(offsets[0], 2); // freed → bucket 1 has 1 slot
    assert!(s.alloc(2, AllocSide::Lo, 0).is_some()); // reuses freed slot
    assert!(s.alloc(2, AllocSide::Lo, 0).is_none()); // truly full again
}

#[test]
fn suballoc_uninitialised_pool_acts_unbounded() {
    let mut s = Suballocator::default();
    // pool_bytes=0; the suballoc shouldn't reject any allocation since the
    // model hasn't been told its budget yet.
    for _ in 0..1000 {
        assert!(s.alloc(2, AllocSide::Lo, 0).is_some());
    }
    assert!(s.text_has_room(usize::MAX / 2));
}

#[test]
fn suballoc_rejects_invalid_sizes_and_ignores_null_free() {
    let mut s = Suballocator::default();
    assert_eq!(s.alloc(0, AllocSide::Lo, 0), None);
    assert_eq!(s.alloc(MAX_BUCKET_UNITS + 1, AllocSide::Lo, 0), None);
    s.free(NULL_OFFSET, 1);
    s.free(1, 0);
    s.free(1, MAX_BUCKET_UNITS + 1);
    assert!(s.free_lists.iter().all(|list| list.is_empty()));
}

#[test]
fn hi_side_reuses_a_header_only_after_bump_space_is_exhausted() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    let old = s.alloc(1, AllocSide::Hi, 0).unwrap();
    s.free(old, 1);
    assert_ne!(s.alloc(1, AllocSide::Hi, 0), Some(old));
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Hi, 0).unwrap();
    }
    assert_eq!(s.alloc(1, AllocSide::Hi, 0), Some(old));
}

#[test]
fn hi_side_exhaustion_without_a_free_header_uses_rare_allocation() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Hi, 0).unwrap();
    }
    let before = s.units_start;
    assert_eq!(s.alloc(1, AllocSide::Hi, 0), Some(before - 1));
}

#[test]
fn rare_allocation_splits_larger_free_block() {
    let mut s = Suballocator::default();
    s.reset(32 * ALLOC_UNIT_BYTES);
    // Exhaust the ordinary unit interval. Keep one six-unit block free
    // and suppress glue so the rare path must split that exact block.
    let large = s.alloc(6, AllocSide::Lo, 0).unwrap();
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Lo, 0).unwrap();
    }
    s.free(large, 6);
    s.glue_count = 1;
    assert_eq!(s.alloc(1, AllocSide::Lo, 0), Some(large));
    // A six-unit block minus one leaves five, represented as 4 + 1.
    assert!(s.free_lists[3].contains(&(large + 1)));
    assert!(s.free_lists[0].contains(&(large + 5)));
}

#[test]
fn rare_allocation_borrows_text_space() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Lo, 0).unwrap();
    }
    // With no free block, the allocator takes one unit from the text
    // reservation while leaving room for the text pointer.
    let before = s.units_start;
    assert_eq!(s.alloc(1, AllocSide::Lo, 0), Some(before - 1));
    assert_eq!(
        s.text_capacity_bytes,
        (before - 1) as usize * ALLOC_UNIT_BYTES
    );
}

#[test]
fn rare_allocation_stops_when_text_reservation_is_full() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Lo, 0).unwrap();
    }
    let text_end = s.text_capacity_bytes;
    assert_eq!(s.alloc(1, AllocSide::Lo, text_end), None);
}

#[test]
fn cancelled_glue_aborts_rare_allocation() {
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    control.cancel_after_checks(1);
    let mut s = Suballocator {
        read_control: control,
        ..Suballocator::default()
    };
    s.reset(16 * ALLOC_UNIT_BYTES);
    while s.hi_bump > s.lo_bump {
        s.alloc(1, AllocSide::Lo, 0).unwrap();
    }
    s.free_lists[0] = (0..5000).collect::<Vec<_>>().into();
    assert_eq!(s.try_alloc(2, AllocSide::Lo, 0), Err(Error::Cancelled));
    assert!(token.is_cancelled());
}

// Spec §4.3: free blocks that are address-adjacent should merge into a
// larger run during glue, and that merged run should be visible in the
// bucket whose size matches.
#[test]
fn glue_merges_adjacent_free_blocks() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    // Allocate 4 consecutive 1-unit blocks from the Lo side. They will
    // be at offsets [units_start, units_start+1, units_start+2,
    // units_start+3], i.e. adjacent.
    let a = s.alloc(1, AllocSide::Lo, 0).unwrap();
    let b = s.alloc(1, AllocSide::Lo, 0).unwrap();
    let c = s.alloc(1, AllocSide::Lo, 0).unwrap();
    let d = s.alloc(1, AllocSide::Lo, 0).unwrap();
    assert_eq!(b, a + 1);
    assert_eq!(c, a + 2);
    assert_eq!(d, a + 3);
    // Free them — bucket 0 now has 4 entries, bucket 3 (size 4) has none.
    s.free(a, 1);
    s.free(b, 1);
    s.free(c, 1);
    s.free(d, 1);
    assert_eq!(s.free_lists[0].len(), 4);
    assert!(s.free_lists[3].is_empty());
    s.glue();
    // After gluing, the 4-adjacent run becomes one 4-unit block in bucket 3.
    assert!(s.free_lists[0].is_empty());
    assert_eq!(s.free_lists[3].len(), 1);
    // And we can satisfy a 4-unit request from the merged block.
    assert_eq!(s.alloc(4, AllocSide::Lo, 0), Some(a));
}

// Non-adjacent free blocks shouldn't merge even though their bucket sizes
// are compatible.
#[test]
fn glue_keeps_non_adjacent_blocks_separate() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    // Two 1-unit blocks separated by a still-live 2-unit allocation.
    let a = s.alloc(1, AllocSide::Lo, 0).unwrap();
    let _live = s.alloc(2, AllocSide::Lo, 0).unwrap();
    let b = s.alloc(1, AllocSide::Lo, 0).unwrap();
    s.free(a, 1);
    s.free(b, 1);
    s.glue();
    // Still two separate 1-unit free entries; no merged 2-unit block.
    assert_eq!(s.free_lists[0].len(), 2);
}

// A merged run larger than the biggest bucket (128 units) should be
// chunked into multiple bucket-sized pieces during redistribution.
#[test]
fn glue_splits_oversized_run_into_buckets() {
    // 256-unit pool (text=32, bumpable=224). Adjacent 64-unit + 64-unit
    // blocks combine to 128, which is the biggest bucket — exactly one
    // entry. Push it to 192 and we get a 128 + a 64 (closest bucket).
    let mut s = Suballocator::default();
    s.reset(256 * ALLOC_UNIT_BYTES);
    // Three adjacent 64-unit allocs → run of 192 units after freeing.
    // 64 is bucket 18 in the spec table.
    let bucket_64 = Suballocator::bucket_for(64).unwrap();
    assert_eq!(Suballocator::bucket_units(bucket_64), 64);
    let a = s.alloc(64, AllocSide::Lo, 0).unwrap();
    let b = s.alloc(64, AllocSide::Lo, 0).unwrap();
    let c = s.alloc(64, AllocSide::Lo, 0).unwrap();
    assert_eq!(b, a + 64);
    assert_eq!(c, a + 128);
    s.free(a, 64);
    s.free(b, 64);
    s.free(c, 64);
    s.glue();
    // Should emit one 128-unit block + one 64-unit block.
    let bucket_128 = Suballocator::bucket_for(128).unwrap();
    assert_eq!(s.free_lists[bucket_128].len(), 1);
    assert_eq!(s.free_lists[bucket_64].len(), 1);
    // The 128 block starts at `a`, the 64 follows.
    assert_eq!(s.free_lists[bucket_128][0], a);
    assert_eq!(s.free_lists[bucket_64][0], a + 128);
}

#[test]
fn glue_does_not_merge_a_run_to_65536_units() {
    let mut s = Suballocator::default();
    // A 16-bit NU cannot hold 65536 units. Populate the same 512 adjacent
    // 128-unit free blocks without allocating a huge backing pool.
    let bucket = Suballocator::bucket_for(128).unwrap();
    s.free_lists[bucket] = (0..512).map(|i| i * 128).collect::<Vec<_>>().into();
    s.glue();
    assert_eq!(s.free_lists[bucket].len(), 512);
    assert_eq!(s.free_lists[bucket].iter().copied().min(), Some(0));
    assert_eq!(s.free_lists[bucket].iter().copied().max(), Some(511 * 128));
}

#[test]
fn glue_emits_exact_128_unit_chunks_and_inexact_remainder() {
    let mut s = Suballocator::default();
    s.emit_run(10, 256).unwrap();
    let full = Suballocator::bucket_for(128).unwrap();
    assert_eq!(s.free_lists[full], vec![10, 138]);

    // Five units have no dedicated bucket: split into four plus one.
    s.emit_run(300, 5).unwrap();
    assert_eq!(s.free_lists[3], vec![300]);
    assert_eq!(s.free_lists[0], vec![304]);
}

#[test]
fn in_place_split_buckets_an_inexact_five_unit_residue() {
    let mut s = Suballocator::default();
    s.split_in_place(100, 6, 1);
    assert_eq!(s.free_lists[3], vec![101]);
    assert_eq!(s.free_lists[0], vec![105]);
}

// glue_count debounce: a single bump failure runs the glue pass exactly
// once, then subsequent failures decrement instead of re-gluing.
#[test]
fn glue_count_debounces_subsequent_failures() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    // Fill the pool to capacity (14 bumpable units in a 16-unit pool;
    // text region is 2 units). All 14 calls succeed — glue_count stays 0.
    // Pass a text_len that occupies the entire 2-unit text region so
    // the fallback_bump path can't grab any more.
    let text_len_full = 2 * ALLOC_UNIT_BYTES;
    for _ in 0..14 {
        assert!(s.alloc(1, AllocSide::Lo, text_len_full).is_some());
    }
    assert_eq!(s.glue_count, 0);
    // 15th call fails: triggers glue (no-op, no free blocks) then
    // walks up larger buckets (none), then fallback_bump fails (text
    // already fills text region), and on the fallback path we
    // decrement glue_count once. Mirrors C's `p->GlueCount--` inside
    // the bump-fallback branch of AllocUnitsRare.
    assert!(s.alloc(1, AllocSide::Lo, text_len_full).is_none());
    assert_eq!(s.glue_count, GLUE_RESET - 1);
    // Subsequent failure decrements again (no re-glue because count > 0).
    assert!(s.alloc(1, AllocSide::Lo, text_len_full).is_none());
    assert_eq!(s.glue_count, GLUE_RESET - 2);
}

// After exhaustion, freeing two adjacent blocks lets a larger request
// succeed via glue.
#[test]
fn glue_recovers_capacity_for_larger_request() {
    let mut s = Suballocator::default();
    s.reset(16 * ALLOC_UNIT_BYTES);
    // Fill the pool to capacity (14 × 1-unit) without triggering a
    // failure, so glue_count remains 0.
    let mut held = Vec::new();
    for _ in 0..14 {
        held.push(s.alloc(1, AllocSide::Lo, 0).unwrap());
    }
    // Free two adjacent 1-unit blocks at the bottom of the units region.
    s.free(held[0], 1);
    s.free(held[1], 1);
    // alloc(2) needs bucket 1 (size 2). Empty, bump exhausted, but
    // glue_count == 0 so glue fires, merging into one 2-unit block at
    // held[0]. Retry pop succeeds.
    assert_eq!(s.alloc(2, AllocSide::Lo, 0), Some(held[0]));
}

#[test]
fn state_array_units_handles_boundaries() {
    assert_eq!(PpmdDecoder::state_array_units(0), 0);
    assert_eq!(PpmdDecoder::state_array_units(1), 0); // binary: inline
    assert_eq!(PpmdDecoder::state_array_units(2), 1);
    assert_eq!(PpmdDecoder::state_array_units(3), 2);
    assert_eq!(PpmdDecoder::state_array_units(4), 2);
    assert_eq!(PpmdDecoder::state_array_units(255), 128);
    assert_eq!(PpmdDecoder::state_array_units(256), 128);
}

struct Bytes<'a> {
    input: &'a [u8],
}

impl PpmdByteReader for Bytes<'_> {
    fn read_ppmd_byte(&mut self) -> Result<u8> {
        let Some((&byte, rest)) = self.input.split_first() else {
            return Err(Error::NeedMoreInput);
        };
        self.input = rest;
        Ok(byte)
    }
}

#[test]
fn decode_init_rejects_truncated_range_header_without_panic() {
    let mut decoder = PpmdDecoder::new();
    let mut input = Bytes { input: &[0, 0] };
    let mut esc = 0;

    assert_eq!(
        decoder.decode_init(0x20 | 1, &mut input, &mut esc),
        Err(Error::NeedMoreInput)
    );
}

#[test]
fn decode_init_rejects_reuse_before_model_allocation() {
    let mut decoder = PpmdDecoder::new();
    let mut input = Bytes {
        input: &[0, 0, 0, 0],
    };
    let mut esc = 0;

    assert_eq!(
        decoder.decode_init(0, &mut input, &mut esc),
        Err(Error::InvalidData("RAR PPMd block reuses missing model"))
    );
}

#[test]
fn decode_init_accepts_max_wire_order_without_growing_unbounded_model() {
    let mut decoder = PpmdDecoder::new();
    let mut input = Bytes {
        input: &[0, 0, 0, 0, 0],
    };
    let mut esc = 0;

    decoder
        .decode_init(0x20 | 0x1f, &mut input, &mut esc)
        .unwrap();

    assert_eq!(decoder.max_order, 64);
    assert_eq!(decoder.contexts.len(), 1);
    assert_eq!(decoder.contexts[0].states.len(), 256);
    assert_eq!(decoder.max_contexts, model_context_limit(1));
}

#[test]
fn decode_init_rejects_wire_order_one() {
    let mut decoder = PpmdDecoder::new();
    let mut input = Bytes {
        input: &[0, 0, 0, 0, 0],
    };
    let mut esc = 0;
    assert_eq!(
        decoder.decode_init(0x20, &mut input, &mut esc),
        Err(Error::InvalidData("RAR PPMd order is invalid"))
    );
}

#[test]
fn decode_init_reads_explicit_escape_character() {
    let mut decoder = PpmdDecoder::new();
    let mut input = Bytes {
        input: &[0, b'!', 0, 0, 0, 0],
    };
    let mut esc = 2;
    decoder
        .decode_init(0x20 | 0x40 | 3, &mut input, &mut esc)
        .unwrap();
    assert_eq!(esc, b'!');
}

#[test]
fn decoder_reports_invalid_range_and_frequency_sum() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    let mut input = Bytes { input: &[] };
    decoder.range.range = 1;
    assert_eq!(
        decoder.decode_symbol(&mut input),
        Err(Error::InvalidData("RAR PPMd range is invalid"))
    );

    decoder.range.range = 257;
    decoder.contexts[0].summ_freq = 1;
    decoder.range.code = 256 * 257;
    assert_eq!(
        decoder.decode_symbol(&mut input),
        Err(Error::InvalidData("RAR PPMd frequency sum is invalid"))
    );
}

#[test]
fn decoder_rejects_invalid_escape_range_and_symbol() {
    fn escaping_model(code_delta: u32) -> PpmdDecoder {
        let mut decoder = PpmdDecoder::new();
        decoder.init_model(4).unwrap();
        let state = |symbol| State {
            symbol,
            freq: 1,
            successor: Successor::None,
        };
        decoder
            .contexts
            .push(Context {
                states: vec![state(b'a'), state(b'b'), state(b'c')].into(),
                summ_freq: 4,
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap();
        decoder
            .contexts
            .push(Context {
                states: vec![state(b'a'), state(b'b')].into(),
                summ_freq: 3,
                suffix: Some(1),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap();
        decoder.min_context = 2;
        decoder.range.range = 100_000;
        // The first escape leaves a 33_333-unit range straddling TOP.
        // That is above BOT, so normalization consumes no input.
        decoder.range.low = TOP - 20_000 - 2 * (100_000 / 3);
        decoder.range.code = decoder.range.low + code_delta;
        decoder
    }

    let mut decoder = escaping_model(2 * (100_000 / 3));
    decoder.see[0][7] = See {
        summ: u16::MAX,
        shift: 0,
        count: 1,
    };
    assert_eq!(
        decoder.decode_symbol(&mut Bytes { input: &[] }),
        Err(Error::InvalidData("RAR PPMd escape range is invalid"))
    );

    let mut decoder = escaping_model(110_000);
    assert_eq!(
        decoder.decode_symbol(&mut Bytes { input: &[] }),
        Err(Error::InvalidData("RAR PPMd escape symbol is invalid"))
    );
}

#[test]
fn root_escape_ends_ppmd_stream() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    let total = decoder.contexts[0].summ_freq as u32;
    decoder.range.code = 256 * (decoder.range.range / total);
    let mut input = Bytes { input: &[0; 16] };
    assert_eq!(decoder.decode_symbol(&mut input), Ok(None));
}

#[test]
fn range_decoder_rejects_reserved_initial_code() {
    let mut range = RangeDecoder::new();
    let mut input = Bytes { input: &[0xff; 4] };
    assert_eq!(
        range.init(&mut input),
        Err(Error::InvalidData("RAR PPMd range code is invalid"))
    );
}

#[test]
fn range_coders_normalize_across_the_bottom_boundary() {
    let mut decoder = RangeDecoder::new();
    decoder.low = TOP - 50;
    decoder.range = 100;
    decoder.normalize(&mut Bytes { input: &[0; 8] }).unwrap();
    assert_ne!(decoder.range, 100);

    let mut encoder = RangeEncoder::new();
    encoder.low = TOP - 50;
    encoder.range = 100;
    encoder.normalize();
    assert!(!encoder.out.is_empty());

    // Straddling TOP alone does not normalize while enough range remains.
    let mut decoder = RangeDecoder::new();
    decoder.low = TOP - 20_000;
    decoder.range = 40_000;
    decoder.normalize(&mut Bytes { input: &[] }).unwrap();
    assert_eq!(decoder.range, 40_000);

    let mut encoder = RangeEncoder::new();
    encoder.low = TOP - 20_000;
    encoder.range = 40_000;
    encoder.normalize();
    assert!(encoder.out.is_empty());
}

#[test]
fn see_counter_ages_and_dummy_accumulates_without_aging() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder.see[0][0] = See {
        summ: 7,
        shift: PERIOD_BITS - 1,
        count: 1,
    };
    decoder.update_see(SeeRef::Table(0, 0));
    assert_eq!(decoder.see[0][0].summ, 14);
    assert_eq!(decoder.see[0][0].shift, PERIOD_BITS);
    assert_eq!(decoder.see[0][0].count, 3 << (PERIOD_BITS - 1));
    decoder.update_see(SeeRef::Table(0, 0));
    assert_eq!(decoder.see[0][0].summ, 14);

    let before = decoder.dummy_see;
    decoder.update_see(SeeRef::Dummy);
    assert_eq!(decoder.dummy_see.summ, before.summ);
    assert_eq!(decoder.dummy_see.count, before.count);
    decoder.add_see_summ(SeeRef::Dummy, 9);
    assert_eq!(decoder.dummy_see.summ, before.summ + 9);
}

#[test]
fn encoder_rejects_invalid_match_and_repeat_bounds() {
    let mut encoder = PpmdEncoder::new(4, 2, 1).unwrap();
    for length in [3, 260] {
        assert_eq!(
            encoder.encode_repeat_offset_one(length),
            Err(Error::InvalidData(
                "RAR PPMd offset-one repeat length is invalid"
            ))
        );
    }
    for (offset, length) in [(1, 32), (0x1000002, 32), (2, 31), (2, 288)] {
        assert_eq!(
            encoder.encode_match(offset, length),
            Err(Error::InvalidData("RAR PPMd match is invalid"))
        );
    }
}

#[test]
fn encoder_rejects_corrupt_frequency_sum_and_missing_root_symbol() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder.contexts[0].states.truncate(2);
    decoder.contexts[0].summ_freq = 2;
    assert_eq!(
        decoder.encode_symbol(2, &mut RangeEncoder::new()),
        Err(Error::InvalidData("RAR PPMd frequency sum is invalid"))
    );

    decoder.init_model(4).unwrap();
    decoder.contexts[0].states.truncate(2);
    decoder.contexts[0].summ_freq = 3;
    assert_eq!(
        decoder.encode_symbol(2, &mut RangeEncoder::new()),
        Err(Error::InvalidData("RAR PPMd symbol is not encodable"))
    );
}

#[test]
fn encoder_rejects_orders_outside_model_bounds() {
    assert!(matches!(
        PpmdEncoder::new(1, 2, 1),
        Err(Error::InvalidData("RAR PPMd order is invalid"))
    ));
    assert!(matches!(
        PpmdEncoder::new(65, 2, 1),
        Err(Error::InvalidData("RAR PPMd order is invalid"))
    ));
}

#[test]
fn encoder_rejects_zero_dictionary_size() {
    assert!(matches!(
        PpmdEncoder::new(4, 2, 0),
        Err(Error::InvalidData("RAR PPMd dictionary size is invalid"))
    ));
}

#[test]
fn range_decoder_rejects_zero_total_without_panic() {
    let mut decoder = RangeDecoder::new();
    let mut input = Bytes {
        input: &[0, 0, 0, 0],
    };
    decoder.init(&mut input).unwrap();

    assert_eq!(
        decoder.get_threshold(0),
        Err(Error::InvalidData("RAR PPMd frequency sum is zero"))
    );
}

#[test]
fn context_allocation_respects_dictionary_limit() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 1;
    decoder.init_model(4).unwrap();

    assert_eq!(
        decoder
            .push_context(Context {
                states: Buffer::new(&Allowance::default()),
                summ_freq: 0,
                suffix: None,
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap(),
        None
    );
}

#[test]
fn context_header_pressure_is_distinct_from_the_context_count_limit() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = model_context_limit(1);
    decoder.suballoc.reset(1024 * 1024);
    decoder.init_model(4).unwrap();

    // Occupy the pool through the allocator's normal state-array and
    // header operations, including its rare text-reservation fallback.
    // The root's 128-unit array alone makes memory bind before the
    // defensive one-header-per-unit context-count cap.
    while decoder.suballoc.alloc(128, AllocSide::Lo, 0).is_some() {}
    while decoder.suballoc.alloc(1, AllocSide::Hi, 0).is_some() {}
    assert!(decoder.contexts.len() < decoder.max_contexts);
    let root_header = decoder.contexts[0].header_offset;
    let root_array = decoder.contexts[0].array_offset;
    let new_context = || Context {
        states: vec![State {
            symbol: b'a',
            freq: 1,
            successor: Successor::None,
        }]
        .into(),
        summ_freq: 0,
        suffix: Some(0),
        header_offset: NULL_OFFSET,
        array_offset: NULL_OFFSET,
    };
    assert_eq!(decoder.push_context(new_context()).unwrap(), None);
    assert_eq!(decoder.contexts.len(), 1);
    assert_eq!(decoder.contexts[0].header_offset, root_header);
    assert_eq!(decoder.contexts[0].array_offset, root_array);
    assert_eq!(decoder.contexts[0].states.len(), 256);

    decoder.init_model(4).unwrap();
    assert_eq!(decoder.push_context(new_context()).unwrap(), Some(1));
}

#[test]
fn context_allocation_releases_header_when_state_array_does_not_fit() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 10;
    decoder.suballoc.reset(16 * ALLOC_UNIT_BYTES);
    let state = State {
        symbol: 0,
        freq: 1,
        successor: Successor::None,
    };
    let context = Context {
        states: vec![state; 256].into(),
        summ_freq: 257,
        suffix: None,
        header_offset: NULL_OFFSET,
        array_offset: NULL_OFFSET,
    };
    assert_eq!(decoder.push_context(context).unwrap(), None);
    assert_eq!(decoder.suballoc.free_lists[0].len(), 1);
    assert!(decoder.contexts.is_empty());
}

#[test]
fn model_restarts_at_text_boundary_and_failed_successor_creation() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder.suballoc.reset(16 * ALLOC_UNIT_BYTES);
    decoder
        .text
        .resize(decoder.suballoc.text_capacity_bytes - 1, 0)
        .unwrap();
    decoder.update_model().unwrap();
    assert!(decoder.text.is_empty());
    assert_eq!(decoder.contexts.len(), 1);

    decoder.order_fall = 0;
    decoder.update_model().unwrap();
    assert_eq!(decoder.order_fall, 4);

    decoder.contexts[0].states[0].successor = Successor::Raw(usize::MAX);
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[0].states[0].successor, Successor::None);
}

#[test]
fn model_restarts_when_an_ancestor_state_array_cannot_grow() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 10;
    decoder.init_model(4).unwrap();
    let state = |symbol| State {
        symbol,
        freq: 1,
        successor: Successor::None,
    };
    let ancestor = decoder
        .push_context(Context {
            states: vec![state(b'a'), state(b'b')].into(),
            summ_freq: 3,
            suffix: Some(0),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap()
        .unwrap();
    let selected = decoder
        .push_context(Context {
            states: vec![state(b'c'), state(b'd')].into(),
            summ_freq: 3,
            suffix: Some(ancestor),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap()
        .unwrap();
    let expanded = decoder
        .push_context(Context {
            states: vec![state(b'a'), state(b'b')].into(),
            summ_freq: 3,
            suffix: Some(selected),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap()
        .unwrap();
    decoder.min_context = selected;
    decoder.max_context = expanded;
    decoder.found_state = StateRef {
        context: selected,
        index: 0,
    };
    decoder.order_fall = 1;

    decoder.suballoc.reset(16 * ALLOC_UNIT_BYTES);
    decoder
        .text
        .resize(decoder.suballoc.text_capacity_bytes - 2, 0)
        .unwrap();
    while decoder.suballoc.hi_bump > decoder.suballoc.lo_bump {
        decoder.suballoc.alloc(1, AllocSide::Lo, 0).unwrap();
    }
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts.len(), 1);
    assert_eq!(decoder.order_fall, 4);
    assert!(decoder.text.is_empty());
}

#[test]
fn model_adds_ancestor_state_with_raw_or_context_successor() {
    fn chain(existing_successor: Successor) -> (PpmdDecoder, usize) {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 10;
        decoder.init_model(4).unwrap();
        let state = |symbol, successor| State {
            symbol,
            freq: 1,
            successor,
        };
        let ancestor = decoder
            .push_context(Context {
                states: vec![state(b'a', Successor::None), state(b'b', Successor::None)].into(),
                summ_freq: 3,
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        let selected = decoder
            .push_context(Context {
                states: vec![
                    state(b'c', existing_successor),
                    state(b'd', Successor::None),
                ]
                .into(),
                summ_freq: 3,
                suffix: Some(ancestor),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        let expanded = decoder
            .push_context(Context {
                states: vec![state(b'a', Successor::None), state(b'b', Successor::None)].into(),
                summ_freq: 3,
                suffix: Some(selected),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        decoder.min_context = selected;
        decoder.max_context = expanded;
        decoder.found_state = StateRef {
            context: selected,
            index: 0,
        };
        decoder.order_fall = 1;
        (decoder, expanded)
    }

    let (mut decoder, expanded) = chain(Successor::None);
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[expanded].states.len(), 3);
    assert_eq!(
        decoder.contexts[expanded].states[2].successor,
        Successor::Raw(1)
    );
    assert_eq!(&*decoder.text, b"c");

    let (mut decoder, expanded) = chain(Successor::Context(2));
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[expanded].states.len(), 3);
    assert_eq!(
        decoder.contexts[expanded].states[2].successor,
        Successor::Context(2)
    );
    assert!(decoder.text.is_empty());
}

#[test]
fn model_updates_suffix_frequencies_at_the_binary_and_multi_state_caps() {
    fn chain(suffix: Vec<State>, symbol: u8) -> (PpmdDecoder, usize) {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 10;
        decoder.init_model(4).unwrap();
        let ancestor = decoder
            .push_context(Context {
                summ_freq: suffix.iter().map(|s| s.freq as u16).sum::<u16>() + 1,
                states: suffix.into(),
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        let selected = decoder
            .push_context(Context {
                states: vec![State {
                    symbol,
                    freq: 2,
                    successor: Successor::None,
                }]
                .into(),
                summ_freq: 0,
                suffix: Some(ancestor),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        decoder.min_context = selected;
        decoder.max_context = selected;
        decoder.found_state = StateRef {
            context: selected,
            index: 0,
        };
        decoder.order_fall = 1;
        (decoder, ancestor)
    }
    let state = |symbol, freq| State {
        symbol,
        freq,
        successor: Successor::None,
    };

    for (initial, expected) in [(31, 32), (32, 32)] {
        let (mut decoder, ancestor) = chain(vec![state(b'a', initial)], b'a');
        decoder.update_model().unwrap();
        assert_eq!(decoder.contexts[ancestor].states[0].freq, expected);
    }

    let (mut decoder, ancestor) = chain(vec![state(b'a', 2), state(b'b', 2)], b'b');
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[ancestor].states[0].symbol, b'b');
    assert_eq!(decoder.contexts[ancestor].states[0].freq, 4);

    let (mut decoder, ancestor) = chain(vec![state(b'a', 1), state(b'b', 115)], b'b');
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[ancestor].states[0].freq, 115);

    let (mut decoder, ancestor) = chain(vec![state(b'a', 2), state(b'b', 2)], b'c');
    decoder.update_model().unwrap();
    assert_eq!(decoder.contexts[ancestor].states[0].freq, 2);
    assert_eq!(decoder.contexts[ancestor].states[1].freq, 2);
}

#[test]
fn successor_creation_materializes_raw_chain_and_handles_limits() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 10;
    decoder.init_model(4).unwrap();
    let selected = decoder
        .push_context(Context {
            states: vec![State {
                symbol: b'a',
                freq: 2,
                successor: Successor::Raw(0),
            }]
            .into(),
            summ_freq: 0,
            suffix: Some(0),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap()
        .unwrap();
    decoder.contexts[0].states[b'a' as usize].successor = Successor::Raw(0);
    decoder.min_context = selected;
    decoder.found_state = StateRef {
        context: selected,
        index: 0,
    };
    decoder.order_fall = 1;
    decoder.text.push(b'b').unwrap();

    let mut limited = decoder.clone();
    limited.max_contexts = 2;
    assert_eq!(limited.create_successors().unwrap(), None);
    let mut conflicting = decoder.clone();
    conflicting.contexts[0].states[b'a' as usize].successor = Successor::None;
    assert_eq!(conflicting.create_successors().unwrap(), None);

    let leaf = decoder.create_successors().unwrap().unwrap();
    assert_eq!(decoder.contexts.len(), 4);
    assert_eq!(decoder.contexts[leaf].states[0].symbol, b'b');
    assert_eq!(decoder.contexts[leaf].suffix, Some(2));
    assert_eq!(
        decoder.contexts[0].states[b'a' as usize].successor,
        Successor::Context(2)
    );
    assert_eq!(
        decoder.contexts[selected].states[0].successor,
        Successor::Context(leaf)
    );
}

#[test]
fn successor_creation_reuses_existing_context_without_materialization() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 4;
    decoder.init_model(4).unwrap();
    let selected = decoder
        .push_context(Context {
            states: vec![State {
                symbol: b'a',
                freq: 2,
                successor: Successor::Raw(0),
            }]
            .into(),
            summ_freq: 0,
            suffix: Some(0),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap()
        .unwrap();
    decoder.min_context = selected;
    decoder.found_state = StateRef {
        context: selected,
        index: 0,
    };
    decoder.order_fall = 0;
    decoder.contexts[0].states[b'a' as usize].successor = Successor::Context(0);
    assert_eq!(decoder.create_successors().unwrap(), Some(0));
    assert_eq!(decoder.contexts.len(), 2);

    decoder.contexts[selected].states[0].successor = Successor::Context(0);
    assert_eq!(decoder.create_successors().unwrap(), Some(0));
    decoder.order_fall = 1;
    assert_eq!(decoder.create_successors().unwrap(), None);
    decoder.order_fall = 0;
    decoder.contexts[selected].states[0].successor = Successor::None;
    assert_eq!(decoder.create_successors().unwrap(), None);

    decoder.min_context = 0;
    decoder.found_state = StateRef {
        context: 0,
        index: 0,
    };
    decoder.contexts[0].states[0].successor = Successor::Raw(0);
    assert_eq!(decoder.create_successors().unwrap(), Some(0));
}

#[test]
fn cancelled_model_init_does_not_erase_contexts() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    let token = crate::ReadCancellation::new();
    decoder.set_read_control(crate::read_control::ReadControl::new(Some(&token)));
    token.cancel();
    assert_eq!(decoder.init_model(8), Err(Error::Cancelled));
    assert_eq!(decoder.max_order, 4);
    assert_eq!(decoder.contexts.len(), 1);
}

#[test]
fn shrink_array_reuses_a_free_bucket_or_splits_in_place() {
    let mut decoder = PpmdDecoder::new();
    decoder.max_contexts = 4;
    let state = State {
        symbol: 0,
        freq: 1,
        successor: Successor::None,
    };
    let context = Context {
        states: vec![state; 12].into(),
        summ_freq: 13,
        suffix: None,
        header_offset: NULL_OFFSET,
        array_offset: NULL_OFFSET,
    };
    let ctx = decoder.push_context(context).unwrap().unwrap();
    let original = decoder.contexts[ctx].array_offset;
    decoder.shrink_state_array(ctx, 12, 12).unwrap();
    assert_eq!(decoder.contexts[ctx].array_offset, original);
    // Six and five units share a bucket, so this shrink keeps its slot.
    decoder.shrink_state_array(ctx, 12, 10).unwrap();
    assert_eq!(decoder.contexts[ctx].array_offset, original);

    // Six to two units has no spare block: keep the prefix and free the
    // four-unit residue. A spare two-unit block later selects the swap.
    decoder.shrink_state_array(ctx, 12, 4).unwrap();
    assert_eq!(decoder.contexts[ctx].array_offset, original);
    assert!(decoder.suballoc.free_lists[3].contains(&(original + 2)));
    let spare = decoder.suballoc.alloc(2, AllocSide::Lo, 0).unwrap();
    decoder.suballoc.free(spare, 2);
    decoder.shrink_state_array(ctx, 12, 4).unwrap();
    assert_eq!(decoder.contexts[ctx].array_offset, spare);
    assert!(decoder.suballoc.free_lists[4].contains(&original));

    decoder.shrink_state_array(ctx, 4, 1).unwrap();
    assert_eq!(decoder.contexts[ctx].array_offset, NULL_OFFSET);
}

#[test]
fn rescale_sorts_survivors_and_collapses_or_shrinks_arrays() {
    fn model(
        freqs: &[(u8, u8)],
        sum: u16,
        order_fall: usize,
        found: usize,
    ) -> (PpmdDecoder, usize) {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 4;
        decoder.init_model(4).unwrap();
        let ctx = decoder
            .push_context(Context {
                states: freqs
                    .iter()
                    .map(|&(symbol, freq)| State {
                        symbol,
                        freq,
                        successor: Successor::None,
                    })
                    .collect::<Vec<_>>()
                    .into(),
                summ_freq: sum,
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        decoder.min_context = ctx;
        decoder.found_state = StateRef {
            context: ctx,
            index: found,
        };
        decoder.order_fall = order_fall;
        (decoder, ctx)
    }

    let (mut decoder, ctx) = model(&[(b'a', 10), (b'b', 1), (b'c', 80)], 92, 1, 0);
    decoder.rescale().unwrap();
    assert_eq!(
        decoder.contexts[ctx]
            .states
            .iter()
            .map(|s| (s.symbol, s.freq))
            .collect::<Vec<_>>(),
        vec![(b'c', 40), (b'a', 7), (b'b', 1)]
    );
    assert_eq!(decoder.contexts[ctx].summ_freq, 49);

    let (mut decoder, ctx) = model(&[(b'a', 10), (b'b', 125), (b'c', 2)], 138, 1, 1);
    decoder.rescale().unwrap();
    assert_eq!(decoder.found_state.index, 0);
    assert_eq!(decoder.contexts[ctx].states[0].symbol, b'b');
    assert_eq!(decoder.contexts[ctx].states[0].freq, 65);

    let (mut decoder, ctx) = model(&[(b'a', 125), (b'b', 1), (b'c', 1)], 130, 0, 0);
    decoder.rescale().unwrap();
    assert_eq!(decoder.contexts[ctx].states.len(), 1);
    assert_eq!(decoder.contexts[ctx].states[0].freq, 16);
    assert_eq!(decoder.contexts[ctx].array_offset, NULL_OFFSET);

    let (mut decoder, ctx) = model(&[(b'a', 125), (b'b', 2), (b'c', 1)], 130, 0, 0);
    let old_array = decoder.contexts[ctx].array_offset;
    decoder.rescale().unwrap();
    assert_eq!(
        decoder.contexts[ctx]
            .states
            .iter()
            .map(|s| (s.symbol, s.freq))
            .collect::<Vec<_>>(),
        vec![(b'a', 64), (b'b', 1)]
    );
    assert_eq!(decoder.contexts[ctx].summ_freq, 67);
    assert_eq!(decoder.contexts[ctx].array_offset, old_array);
    assert!(decoder.suballoc.free_lists[0].contains(&(old_array + 1)));
}

#[test]
fn frequency_updates_rescale_at_the_reference_call_sites() {
    fn model(freqs: &[(u8, u8)], selected: usize) -> (PpmdDecoder, usize) {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 4;
        decoder.init_model(4).unwrap();
        let ctx = decoder
            .push_context(Context {
                states: freqs
                    .iter()
                    .map(|&(symbol, freq)| State {
                        symbol,
                        freq,
                        successor: Successor::None,
                    })
                    .collect::<Vec<_>>()
                    .into(),
                summ_freq: freqs.iter().map(|&(_, freq)| freq as u16).sum::<u16>() + 1,
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        for state in &mut decoder.contexts[ctx].states {
            state.successor = Successor::Context(ctx);
        }
        decoder.min_context = ctx;
        decoder.max_context = ctx;
        decoder.found_state = StateRef {
            context: ctx,
            index: selected,
        };
        decoder.order_fall = 0;
        (decoder, ctx)
    }

    let (mut decoder, ctx) = model(&[(b'a', 121), (b'b', 1)], 0);
    decoder.update1_0().unwrap();
    assert_eq!(decoder.contexts[ctx].states.len(), 1);

    let (mut decoder, ctx) = model(&[(b'a', 1), (b'b', 121)], 1);
    decoder.update1().unwrap();
    assert_eq!(decoder.contexts[ctx].states.len(), 1);

    // Variant H rescales update1 only when the selected state moves
    // ahead of its predecessor, even if its frequency now exceeds 124.
    let (mut decoder, ctx) = model(&[(b'a', 125), (b'b', 121)], 1);
    decoder.update1().unwrap();
    assert_eq!(decoder.contexts[ctx].states[1].freq, 125);
    assert_eq!(decoder.contexts[ctx].states.len(), 2);

    let (mut decoder, ctx) = model(&[(b'a', 121), (b'b', 1)], 0);
    decoder.update2().unwrap();
    assert_eq!(decoder.contexts[ctx].states.len(), 1);

    let (mut decoder, ctx) = model(&[(b'a', 127)], 0);
    decoder.update_bin().unwrap();
    assert_eq!(decoder.contexts[ctx].states[0].freq, 128);
    decoder.update_bin().unwrap();
    assert_eq!(decoder.contexts[ctx].states[0].freq, 128);
}

#[test]
fn make_esc_freq_rejects_invalid_masked_state_count() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder
        .contexts
        .push(Context {
            states: vec![
                State {
                    symbol: b'a',
                    freq: 1,
                    successor: Successor::None,
                },
                State {
                    symbol: b'b',
                    freq: 1,
                    successor: Successor::None,
                },
            ]
            .into(),
            summ_freq: 2,
            suffix: Some(0),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap();
    decoder.min_context = 1;

    assert!(matches!(
        decoder.make_esc_freq(2),
        Err(Error::InvalidData("RAR PPMd masked-state count is invalid"))
    ));
}

#[test]
fn update_model_rejects_invalid_frequency_arithmetic() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder
        .contexts
        .push(Context {
            states: vec![State {
                symbol: b'a',
                freq: 10,
                successor: Successor::None,
            }]
            .into(),
            summ_freq: 1,
            suffix: Some(0),
            header_offset: NULL_OFFSET,
            array_offset: NULL_OFFSET,
        })
        .unwrap();
    decoder.min_context = 1;
    decoder.max_context = 0;
    decoder.found_state = StateRef {
        context: 1,
        index: 0,
    };
    decoder.order_fall = 1;

    assert!(matches!(
        decoder.update_model(),
        Err(Error::InvalidData("RAR PPMd model frequency is invalid"))
    ));
}

#[test]
fn update_model_rejects_zero_frequency_sum_and_unrepresentable_sum() {
    fn chain(
        ancestor: Vec<State>,
        ancestor_sum: u16,
        selected: Vec<State>,
        selected_sum: u16,
    ) -> PpmdDecoder {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 10;
        decoder.init_model(4).unwrap();
        let ancestor = decoder
            .push_context(Context {
                states: ancestor.into(),
                summ_freq: ancestor_sum,
                suffix: Some(0),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        let selected = decoder
            .push_context(Context {
                states: selected.into(),
                summ_freq: selected_sum,
                suffix: Some(ancestor),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })
            .unwrap()
            .unwrap();
        decoder.min_context = selected;
        decoder.max_context = ancestor;
        decoder.found_state = StateRef {
            context: selected,
            index: 0,
        };
        decoder.order_fall = 1;
        decoder
    }
    let state = |symbol, freq| State {
        symbol,
        freq,
        successor: Successor::None,
    };

    let mut decoder = chain(
        vec![state(b'a', 0)],
        0,
        vec![state(b'c', 31), state(b'd', 1)],
        32,
    );
    assert_eq!(
        decoder.update_model(),
        Err(Error::InvalidData("RAR PPMd model frequency is invalid"))
    );

    let selected = (0..10)
        .map(|i| state(b'c' + i, if i == 0 { 31 } else { 1 }))
        .collect();
    let mut decoder = chain(vec![state(b'a', 1), state(b'b', 1)], u16::MAX, selected, 40);
    assert_eq!(
        decoder.update_model(),
        Err(Error::InvalidData("RAR PPMd model frequency overflows"))
    );
}

#[test]
fn update_paths_reject_invalid_state_reference_without_panic() {
    let mut decoder = PpmdDecoder::new();
    decoder.init_model(4).unwrap();
    decoder.found_state = StateRef {
        context: 99,
        index: 0,
    };

    assert_eq!(
        decoder.update1_0(),
        Err(Error::InvalidData("RAR PPMd state reference is invalid"))
    );

    decoder.found_state = StateRef {
        context: 0,
        index: 999,
    };
    assert_eq!(
        decoder.update_bin(),
        Err(Error::InvalidData("RAR PPMd state reference is invalid"))
    );
}
