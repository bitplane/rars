//! Custom RAR 3 filter programs are held to an instruction budget in
//! proportion to the bytes they filter (issue #540).
use super::super::rarvm::{
    self, Instruction, Invocation, Opcode, Operand, Program, VmWork, MAX_INSTRUCTIONS,
    VM_WORK_ARCHIVE_FLOOR, VM_WORK_MEMBER_FLOOR, VM_WORK_PER_BYTE,
};
use super::{
    audio_encode, encode_member_with_custom_filters, itanium_encode, rgb_encode, Error, Unpack29,
    COUNTDOWN_VM_PROGRAM, RAR3_AUDIO_FILTER_BYTECODE, RAR3_DELTA_FILTER_BYTECODE,
    RAR3_E8E9_FILTER_BYTECODE, RAR3_E8_FILTER_BYTECODE, RAR3_ITANIUM_FILTER_BYTECODE,
    RAR3_RGB_FILTER_BYTECODE,
};
use crate::read_control::ReadControl;
use crate::ArchiveReadOptions;

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn instructions(code: &[u8], input: &[u8], regs: [u32; 7]) -> usize {
    Program::parse(code)
        .unwrap()
        .execute(Invocation {
            input,
            regs,
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap()
        .instructions
}

#[test]
fn the_countdown_program_is_dec_jnz() {
    let program = Program::parse(COUNTDOWN_VM_PROGRAM).unwrap();
    assert_eq!(
        program.instructions,
        [
            Instruction {
                opcode: Opcode::Dec,
                byte_mode: false,
                operands: vec![Operand::Register(0)],
            },
            Instruction {
                opcode: Opcode::Jnz,
                byte_mode: false,
                operands: vec![Operand::Immediate(0)],
            },
            Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: vec![],
            },
        ]
    );
    // Two instructions a step, then the final `jnz` falls through to `ret`.
    assert_eq!(
        instructions(COUNTDOWN_VM_PROGRAM, &[0], [5, 0, 0, 0, 0, 0, 0]),
        11
    );
}

/// A program, its input and its registers.
type Case<'a> = (&'a str, &'a [u8], Vec<u8>, [u32; 7]);

/// The six standard programs run natively and never reach the budget, but
/// they are what WinRAR wrote, so they say what a real program costs. Each
/// runs here in the VM over the input that costs it most per byte we found,
/// and must fit four times over in the per-byte allowance alone.
#[test]
fn standard_programs_fit_the_budget_four_times_over() {
    const LEN: usize = 60_000;
    let random = noise(LEN, 7);
    let e8 = vec![0xe8; LEN];
    let e8e9: Vec<u8> = (0..LEN).map(|i| [0xe8, 0xe9][i % 2]).collect();
    let mut itanium = vec![0u8; LEN];
    for bundle in itanium.as_chunks_mut::<16>().0 {
        // Bundles shaped like those the Itanium bytecode test rewrites.
        bundle[0] = 0x16;
        bundle[5] = 0x50;
        bundle[10] = 0x0a;
    }
    itanium_encode(&mut itanium, 0);
    let mut cases: Vec<Case> = vec![
        ("e8 random", RAR3_E8_FILTER_BYTECODE, random.clone(), [0; 7]),
        ("e8 dense", RAR3_E8_FILTER_BYTECODE, e8.clone(), [0; 7]),
        (
            "e8e9 random",
            RAR3_E8E9_FILTER_BYTECODE,
            random.clone(),
            [0; 7],
        ),
        ("e8e9 dense", RAR3_E8E9_FILTER_BYTECODE, e8e9, [0; 7]),
        (
            "itanium random",
            RAR3_ITANIUM_FILTER_BYTECODE,
            random.clone(),
            [0; 7],
        ),
        (
            "itanium branches",
            RAR3_ITANIUM_FILTER_BYTECODE,
            itanium,
            [0; 7],
        ),
    ];
    for channels in [1, 3, 64] {
        cases.push((
            "delta",
            RAR3_DELTA_FILTER_BYTECODE,
            random.clone(),
            [channels, 0, 0, 0, 0, 0, 0],
        ));
    }
    for (width, pos_r) in [(3usize, 0usize), (300, 2)] {
        cases.push((
            "rgb",
            RAR3_RGB_FILTER_BYTECODE,
            rgb_encode(&random, width, pos_r).unwrap(),
            [width as u32 + 3, pos_r as u32, 0, 0, 0, 0, 0],
        ));
    }
    for channels in [1usize, 2, 6] {
        cases.push((
            "audio",
            RAR3_AUDIO_FILTER_BYTECODE,
            audio_encode(&random, channels).unwrap(),
            [channels as u32, 0, 0, 0, 0, 0, 0],
        ));
    }
    for (name, code, input, regs) in cases {
        let used = instructions(code, &input, regs);
        let per_byte = used as f64 / input.len() as f64;
        println!("{name} {:?}: {per_byte:.2} instructions a byte", &regs[..2]);
        assert!(
            used as u64 * 4 <= VM_WORK_PER_BYTE * input.len() as u64,
            "{name}: {per_byte:.2} instructions a byte"
        );
    }
}

fn custom_decoder(options: ArchiveReadOptions<'_>) -> Unpack29 {
    let mut decoder = Unpack29::new();
    decoder.read_control = ReadControl::for_options(&options.with_rar3_vm_programs(true));
    decoder
}

/// A member of `len` bytes with a countdown filter over each of its first
/// `filters` bytes, each run `steps` steps long.
fn countdown_member(len: usize, filters: usize, steps: u32) -> (Vec<u8>, Vec<u8>) {
    let data = noise(len, 11);
    let ranges: Vec<_> = (0..filters).map(|i| (i..i + 1, steps)).collect();
    let packed = encode_member_with_custom_filters(&data, COUNTDOWN_VM_PROGRAM, &ranges).unwrap();
    (data, packed)
}

/// What the operation's budget has spent so far.
fn spent(decoder: &Unpack29) -> u64 {
    decoder
        .read_control
        .with_vm_work(|work| work.used())
        .unwrap()
}

/// A couple of kilobytes buy one filter a byte, each just inside the
/// per-run limit. Before the budget, this member cost 64 whole runs, about
/// ten seconds in a release build.
#[test]
fn many_filters_over_single_bytes_are_refused_within_the_budget() {
    let steps = (MAX_INSTRUCTIONS as u32 - 2) / 2;
    let (_, packed) = countdown_member(256, 64, steps);
    assert!(packed.len() < 1024, "{} bytes", packed.len());
    let mut decoder = custom_decoder(ArchiveReadOptions::new());
    assert_eq!(
        decoder.decode_non_solid_member(&packed, 256),
        Err(Error::Rar3VmWorkLimitExceeded)
    );
    // The first run spends the member's floor and the byte it covers.
    assert_eq!(spent(&decoder), VM_WORK_MEMBER_FLOOR + VM_WORK_PER_BYTE);
}

/// Runs within the budget decode as before, and one run may still reach the
/// per-run limit when its block pays for it.
#[test]
fn programs_within_the_budget_still_run() {
    // Ten instructions a byte over 64 KiB, then a hundred over one byte.
    let len = 64 * 1024;
    let data = noise(len, 3);
    let packed = encode_member_with_custom_filters(
        &data,
        COUNTDOWN_VM_PROGRAM,
        &[(0..len - 1, 5 * len as u32), (len - 1..len, 50)],
    )
    .unwrap();
    let mut decoder = custom_decoder(ArchiveReadOptions::new());
    assert_eq!(decoder.decode_non_solid_member(&packed, len).unwrap(), data);
    assert_eq!(spent(&decoder), (10 * len + 1) as u64 + 101);

    // 128 KiB pays for a whole run, which fails on the per-run limit as it
    // always did.
    let len = 128 * 1024;
    assert!(VM_WORK_PER_BYTE * len as u64 >= MAX_INSTRUCTIONS as u64);
    let packed =
        encode_member_with_custom_filters(&noise(len, 5), COUNTDOWN_VM_PROGRAM, &[(0..len, 0)])
            .unwrap();
    let mut decoder = custom_decoder(ArchiveReadOptions::new());
    assert_eq!(
        decoder.decode_non_solid_member(&packed, len),
        Err(rarvm::INSTRUCTION_LIMIT_EXCEEDED)
    );
    assert_eq!(spent(&decoder), MAX_INSTRUCTIONS as u64);
}

/// Salvage reports the budget once the member has decoded, and leaves the
/// blocks of the filters it skipped as they were. Past the budget, each
/// filter costs only what its own byte allows.
#[test]
fn salvage_skips_filters_past_the_budget_and_reports_it() {
    let (data, packed) = countdown_member(4096, 256, 0);
    let mut decoder = custom_decoder(ArchiveReadOptions::new().with_salvage(true));
    let mut out = Vec::new();
    decoder.state.read_control = decoder.read_control.clone();
    assert_eq!(
        decoder
            .state
            .decode_non_solid_member_to(&packed, data.len(), &mut out),
        Err(Error::Rar3VmWorkLimitExceeded)
    );
    // The countdown leaves its block alone, skipped or not.
    assert_eq!(out, data);
    assert_eq!(
        spent(&decoder),
        VM_WORK_MEMBER_FLOOR + 256 * VM_WORK_PER_BYTE
    );
}

/// Members of one operation share a budget besides their own, so the floor
/// each member gets does not multiply with the member count.
#[test]
fn members_share_an_operation_budget() {
    let (data, packed) = countdown_member(64, 1, 0);
    let mut decoder = custom_decoder(ArchiveReadOptions::new());
    let members = VM_WORK_ARCHIVE_FLOOR / VM_WORK_MEMBER_FLOOR + 3;
    for _ in 0..members {
        assert_eq!(
            decoder.decode_non_solid_member(&packed, data.len()),
            Err(Error::Rar3VmWorkLimitExceeded)
        );
    }
    assert_eq!(
        spent(&decoder),
        VM_WORK_ARCHIVE_FLOOR + members * VM_WORK_PER_BYTE
    );
}

/// Grants saturate rather than wrap.
#[test]
fn vm_work_saturates() {
    let mut work = VmWork::with_floor(u64::MAX - 1);
    work.grant(usize::MAX);
    work.spend(3);
    assert_eq!(work.available(), u64::MAX - 3);
}
