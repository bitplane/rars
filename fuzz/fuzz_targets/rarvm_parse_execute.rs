#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::codec::rarvm::{Invocation, Program};

const MAX_PROGRAM_BYTES: usize = 4096;
const MAX_FILTER_INPUT: usize = 4096;
const MAX_INSTRUCTIONS_TO_EXECUTE: usize = 256;

fuzz_target!(|data: &[u8]| {
    let program_len = data.len().min(MAX_PROGRAM_BYTES);
    let Ok(program) = Program::parse(&data[..program_len]) else {
        return;
    };
    if program.instructions.len() > MAX_INSTRUCTIONS_TO_EXECUTE {
        return;
    }
    let input_len = data.len().min(MAX_FILTER_INPUT);
    let _ = program.execute(Invocation {
        input: &data[..input_len],
        regs: [0; 7],
        global_data: &[],
        file_offset: 0,
        exec_count: 0,
    });
});
