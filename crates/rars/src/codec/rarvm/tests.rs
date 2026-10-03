fn reader_vm_blob() -> Vec<u8> {
    let mut bits = BitWriter::new();
    bits.write_bits(1, 1);
    write_vm_number(&mut bits, 2);
    for byte in [0xaa, 0xbb, 0xcc] {
        bits.write_bits(byte, 8);
    }
    for (address, value) in [(0, 0x41), (GLOBAL_BASE as u32 + 0x30, 8)] {
        write_opcode(&mut bits, Opcode::Mov);
        bits.write_bits(0, 1);
        write_absolute(&mut bits, address);
        write_number_immediate(&mut bits, value);
    }
    write_opcode(&mut bits, Opcode::Ret);
    with_xor(bits.finish())
}
fn reader_vm_invocation() -> Invocation<'static> {
    Invocation {
        input: &[1, 2, 3, 4],
        regs: [0; 7],
        global_data: &[],
        file_offset: 0,
        exec_count: 0,
    }
}

#[test]
fn reader_vm_workspace_refusals_release_program_operands_memory_and_results() {
    use crate::codec::workspace::RefusingBudget;
    let blob = reader_vm_blob();
    let run = |budget: &RefusingBudget| -> Result<()> {
        let program = OwnedProgram::parse(&blob, budget)?;
        let mut vm = Vm::with_allowance(&program, reader_vm_invocation(), budget)?;
        let result = vm.run(&program, &crate::read_control::ReadControl::default())?;
        assert_eq!(&*result.output, b"A\0\0\0");
        assert_eq!(result.globals.len(), SYSTEM_GLOBAL_SIZE + 8);
        Ok(())
    };
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    let attempts = baseline.attempts();
    assert!(attempts >= 7);
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
fn reader_vm_workspace_results_remain_charged_after_worker_retirement() {
    use crate::codec::workspace::RESERVATION_BYTES;
    let ledger = Allowance::limited(1024 * 1024 + RESERVATION_BYTES);
    let mut reservation = ledger.reserve(1024 * 1024).unwrap();
    let budget = reservation.allowance();
    reservation.start();
    let program = OwnedProgram::parse(&reader_vm_blob(), &budget).unwrap();
    let mut vm = Vm::with_allowance(&program, reader_vm_invocation(), &budget).unwrap();
    let result = vm
        .run(&program, &crate::read_control::ReadControl::default())
        .unwrap();
    reservation.retire();
    assert!(ledger.used() >= MEMORY_SIZE as u64 + RESERVATION_BYTES);
    drop(vm);
    drop(program);
    assert_eq!(
        ledger.used(),
        (result.output.capacity() + result.globals.capacity()) as u64 + RESERVATION_BYTES
    );
    drop(result);
    assert_eq!(ledger.used(), RESERVATION_BYTES);
    drop(budget);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn cancellation_interrupts_vm_work_without_output() {
    let program = Program {
        static_data: vec![],
        instructions: vec![instr(Opcode::Jmp, false, vec![Operand::Immediate(0)])],
    };
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    control.cancel_after_checks(2);
    let err = program
        .execute_with_control(
            Invocation {
                input: &[],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            },
            &control,
        )
        .unwrap_err();
    assert_eq!(err, Error::Cancelled);
}

#[test]
fn rejects_a_program_that_exhausts_its_instruction_allowance() {
    let program = Program {
        static_data: vec![],
        instructions: vec![instr(Opcode::Jmp, false, vec![Operand::Immediate(0)])],
    };
    let invocation = Invocation {
        input: &[],
        regs: [0; 7],
        global_data: &[],
        file_offset: 0,
        exec_count: 0,
    };
    let mut vm = Vm::new(&program, invocation).unwrap();

    assert!(matches!(
        vm.run_with_limit(&program, &crate::read_control::ReadControl::default(), 3),
        Err(Error::InvalidData("RARVM instruction limit exceeded"))
    ));
}
use super::*;

#[test]
fn rejects_bad_xor_checksum() {
    assert_eq!(
        Program::parse(&[0x12, 0x34]),
        Err(Error::InvalidData("RARVM program checksum mismatch"))
    );
}

#[test]
fn rejects_an_empty_program_blob() {
    assert_eq!(
        Program::parse(&[]),
        Err(Error::InvalidData("RARVM program blob is empty"))
    );
}

#[test]
fn an_explicitly_empty_program_terminates_without_changing_its_input() {
    let result = Program {
        static_data: Vec::new(),
        instructions: Vec::new(),
    }
    .execute(Invocation {
        input: b"unchanged",
        regs: [0; 7],
        global_data: &[],
        file_offset: 0,
        exec_count: 0,
    })
    .unwrap();

    assert_eq!(result.output, b"unchanged");
}

#[test]
fn parses_static_data_and_appends_implicit_ret() {
    let mut bits = BitWriter::new();
    bits.write_bits(1, 1);
    write_vm_number(&mut bits, 2);
    bits.write_bits(0xaa, 8);
    bits.write_bits(0xbb, 8);
    bits.write_bits(0xcc, 8);
    let program = Program::parse(&with_xor(bits.finish())).unwrap();

    assert_eq!(program.static_data, [0xaa, 0xbb, 0xcc]);
    assert_eq!(
        program.instructions,
        [Instruction {
            opcode: Opcode::Ret,
            byte_mode: false,
            operands: Vec::new(),
        }]
    );
}

#[test]
fn parses_register_immediate_and_memory_operands() {
    let mut bits = BitWriter::new();
    bits.write_bits(0, 1);
    write_opcode(&mut bits, Opcode::Mov);
    bits.write_bits(0, 1);
    write_reg(&mut bits, 2);
    write_number_immediate(&mut bits, 0x1234);
    write_opcode(&mut bits, Opcode::Add);
    bits.write_bits(1, 1);
    write_reg_indirect(&mut bits, 3);
    write_byte_immediate(&mut bits, 0x7f);
    write_opcode(&mut bits, Opcode::Sub);
    bits.write_bits(0, 1);
    write_indexed(&mut bits, 1, 0x44);
    write_absolute(&mut bits, 0x3c000);
    write_opcode(&mut bits, Opcode::Ret);

    let program = Program::parse(&with_xor(bits.finish())).unwrap();
    assert!(program.static_data.is_empty());
    assert_eq!(program.instructions.len(), 4);
    assert_eq!(program.instructions[0].opcode, Opcode::Mov);
    assert!(!program.instructions[0].byte_mode);
    assert_eq!(
        program.instructions[0].operands,
        [Operand::Register(2), Operand::Immediate(0x1234)]
    );
    assert_eq!(program.instructions[1].opcode, Opcode::Add);
    assert!(program.instructions[1].byte_mode);
    assert_eq!(
        program.instructions[1].operands,
        [Operand::RegisterIndirect(3), Operand::Immediate(0x7f)]
    );
    assert_eq!(
        program.instructions[2].operands,
        [
            Operand::Indexed {
                register: 1,
                base: 0x44,
            },
            Operand::Absolute(0x3c000),
        ]
    );
    assert_eq!(program.instructions[3].opcode, Opcode::Ret);
}

#[test]
fn parses_every_long_opcode_used_by_generic_programs() {
    for opcode in [
        Opcode::Xor,
        Opcode::Sar,
        Opcode::Pushf,
        Opcode::Popf,
        Opcode::Div,
        Opcode::Adc,
        Opcode::Sbb,
    ] {
        let mut bits = BitWriter::new();
        bits.write_bits(0, 1); // no static data
        write_opcode(&mut bits, opcode);
        if opcode.supports_byte_mode() {
            bits.write_bits(0, 1);
        }
        for index in 0..opcode.operand_count() {
            write_reg(&mut bits, index as u8);
        }
        write_opcode(&mut bits, Opcode::Ret);

        let program = Program::parse(&with_xor(bits.finish())).unwrap();
        assert_eq!(program.instructions[0].opcode, opcode);
    }
}

#[test]
fn parses_runtime_and_absolute_jump_targets() {
    let mut runtime = BitWriter::new();
    runtime.write_bits(0, 1); // no static data
    write_opcode(&mut runtime, Opcode::Jmp);
    write_reg(&mut runtime, 3);
    let program = Program::parse(&with_xor(runtime.finish())).unwrap();
    assert_eq!(program.instructions[0].operands, [Operand::Register(3)]);

    let mut absolute = BitWriter::new();
    absolute.write_bits(0, 1); // no static data
    write_opcode(&mut absolute, Opcode::Jmp);
    write_number_immediate(&mut absolute, 300);
    let program = Program::parse(&with_xor(absolute.finish())).unwrap();
    assert_eq!(program.instructions[0].operands, [Operand::Immediate(44)]);
}

#[test]
fn ignores_a_trailing_partial_instruction() {
    let mut bits = BitWriter::new();
    bits.write_bits(0, 1); // no static data
    write_opcode(&mut bits, Opcode::Mov);
    bits.write_bits(0, 1); // word mode
    write_reg(&mut bits, 0); // second operand is absent

    let program = Program::parse(&with_xor(bits.finish())).unwrap();
    assert_eq!(
        program.instructions,
        [instr(Opcode::Ret, false, Vec::new())]
    );
}

#[test]
fn remaps_jump_immediates_to_instruction_indices() {
    let mut bits = BitWriter::new();
    bits.write_bits(0, 1);
    write_opcode(&mut bits, Opcode::Print);
    write_opcode(&mut bits, Opcode::Jmp);
    write_number_immediate(&mut bits, 15);

    let program = Program::parse(&with_xor(bits.finish())).unwrap();
    assert_eq!(program.instructions.len(), 2);
    assert_eq!(
        program.instructions[1],
        Instruction {
            opcode: Opcode::Jmp,
            byte_mode: false,
            operands: vec![Operand::Immediate(0)],
        }
    );
}

#[test]
fn executes_arithmetic_and_memory_writes() {
    let program = Program {
        static_data: Vec::new(),
        instructions: vec![
            Instruction {
                opcode: Opcode::Mov,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(7)],
            },
            Instruction {
                opcode: Opcode::Add,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(5)],
            },
            Instruction {
                opcode: Opcode::Mov,
                byte_mode: true,
                operands: vec![Operand::Absolute(0), Operand::Register(0)],
            },
            Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            },
        ],
    };

    let result = program
        .execute(Invocation {
            input: &[0],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap();

    assert_eq!(result.output, [12]);
    assert_eq!(result.regs[0], 12);
}

#[test]
fn executes_conditional_jump_and_stack_call() {
    let program = Program {
        static_data: Vec::new(),
        instructions: vec![
            Instruction {
                opcode: Opcode::Mov,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(1)],
            },
            Instruction {
                opcode: Opcode::Cmp,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(1)],
            },
            Instruction {
                opcode: Opcode::Jz,
                byte_mode: false,
                operands: vec![Operand::Immediate(4)],
            },
            Instruction {
                opcode: Opcode::Mov,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(99)],
            },
            Instruction {
                opcode: Opcode::Call,
                byte_mode: false,
                operands: vec![Operand::Immediate(6)],
            },
            Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            },
            Instruction {
                opcode: Opcode::Add,
                byte_mode: false,
                operands: vec![Operand::Register(0), Operand::Immediate(41)],
            },
            Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            },
        ],
    };

    let result = program
        .execute(Invocation {
            input: &[0],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap();

    assert_eq!(result.regs[0], 42);
}

#[test]
fn nested_calls_return_through_each_stack_frame() {
    let result = execute_instructions(vec![
        instr(Opcode::Call, false, vec![Operand::Immediate(3)]),
        instr(Opcode::Ret, false, Vec::new()),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(99)],
        ),
        instr(Opcode::Call, false, vec![Operand::Immediate(6)]),
        instr(
            Opcode::Add,
            false,
            vec![Operand::Register(0), Operand::Immediate(2)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
        instr(
            Opcode::Add,
            false,
            vec![Operand::Register(0), Operand::Immediate(40)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 42);
}

#[test]
fn executes_unconditional_jumps_and_mutating_unary_ops() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(1)],
        ),
        instr(Opcode::Inc, false, vec![Operand::Register(0)]),
        instr(Opcode::Dec, false, vec![Operand::Register(0)]),
        instr(Opcode::Not, false, vec![Operand::Register(0)]),
        instr(Opcode::Neg, false, vec![Operand::Register(0)]),
        instr(Opcode::Jmp, false, vec![Operand::Immediate(7)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(99)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 2);
}

#[test]
fn executes_logic_ops_and_test_without_writing_destination() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0b1010)],
        ),
        instr(
            Opcode::Xor,
            false,
            vec![Operand::Register(0), Operand::Immediate(0b1100)],
        ),
        instr(
            Opcode::And,
            false,
            vec![Operand::Register(0), Operand::Immediate(0b0110)],
        ),
        instr(
            Opcode::Or,
            false,
            vec![Operand::Register(0), Operand::Immediate(0b0001)],
        ),
        instr(
            Opcode::Test,
            false,
            vec![Operand::Register(0), Operand::Immediate(0b0100)],
        ),
        instr(Opcode::Jnz, false, vec![Operand::Immediate(7)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(99)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0b0111);
}

#[test]
fn executes_unsigned_conditional_jumps() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(1), Operand::Immediate(2)],
        ),
        instr(Opcode::Jb, false, vec![Operand::Immediate(5)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(99)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
        instr(Opcode::Jbe, false, vec![Operand::Immediate(7)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(98)],
        ),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(3), Operand::Immediate(2)],
        ),
        instr(Opcode::Ja, false, vec![Operand::Immediate(10)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(97)],
        ),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(3), Operand::Immediate(2)],
        ),
        instr(Opcode::Jae, false, vec![Operand::Immediate(13)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(96)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(42)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 42);
}

#[test]
fn executes_signed_conditional_jumps() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(
            Opcode::Sub,
            false,
            vec![Operand::Register(0), Operand::Immediate(1)],
        ),
        instr(Opcode::Js, false, vec![Operand::Immediate(5)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(99)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
        instr(
            Opcode::Add,
            false,
            vec![Operand::Register(0), Operand::Immediate(1)],
        ),
        instr(Opcode::Jns, false, vec![Operand::Immediate(8)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(98)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(42)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0);
    assert_eq!(result.regs[1], 42);
}

#[test]
fn executes_stack_register_and_flag_round_trips() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(10)],
        ),
        instr(Opcode::Push, false, vec![Operand::Register(0)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(Opcode::Pop, false, vec![Operand::Register(1)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(10)],
        ),
        instr(Opcode::Pusha, false, Vec::new()),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(99)],
        ),
        instr(Opcode::Popa, false, Vec::new()),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(1), Operand::Immediate(2)],
        ),
        instr(Opcode::Pushf, false, Vec::new()),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(2), Operand::Immediate(2)],
        ),
        instr(Opcode::Popf, false, Vec::new()),
        instr(Opcode::Jb, false, vec![Operand::Immediate(14)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(99)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 10);
    assert_eq!(result.regs[1], 10);
}

#[test]
fn executes_shifts_with_byte_and_word_modes() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0x81)],
        ),
        instr(
            Opcode::Shl,
            false,
            vec![Operand::Register(0), Operand::Immediate(1)],
        ),
        instr(
            Opcode::Shr,
            false,
            vec![Operand::Register(0), Operand::Immediate(2)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0x80)],
        ),
        instr(
            Opcode::Sar,
            true,
            vec![Operand::Register(1), Operand::Immediate(1)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0x40);
    assert_eq!(result.regs[1], 0xc0);
}

#[test]
fn byte_mode_sar_accepts_shift_count_equal_to_width() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0x80)],
        ),
        instr(
            Opcode::Sar,
            true,
            vec![Operand::Register(0), Operand::Immediate(8)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0x7f)],
        ),
        instr(
            Opcode::Sar,
            true,
            vec![Operand::Register(1), Operand::Immediate(8)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0xff);
    assert_eq!(result.regs[1], 0);
}

#[test]
fn word_mode_sar_sign_extends_at_ordinary_and_full_width_counts() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0x8000_0000)],
        ),
        instr(
            Opcode::Sar,
            false,
            vec![Operand::Register(0), Operand::Immediate(1)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0x8000_0000)],
        ),
        instr(
            Opcode::Sar,
            false,
            vec![Operand::Register(1), Operand::Immediate(32)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(2), Operand::Immediate(1)],
        ),
        instr(
            Opcode::Sar,
            false,
            vec![Operand::Register(2), Operand::Immediate(32)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0xc000_0000);
    assert_eq!(result.regs[1], u32::MAX);
    assert_eq!(result.regs[2], 0);
}

#[test]
fn neg_zero_sets_zero_and_divide_by_zero_keeps_the_destination() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(Opcode::Neg, false, vec![Operand::Register(0)]),
        instr(Opcode::Jz, false, vec![Operand::Immediate(4)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(99)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(42)],
        ),
        instr(
            Opcode::Div,
            false,
            vec![Operand::Register(1), Operand::Immediate(0)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0);
    assert_eq!(result.regs[1], 42);
}

#[test]
fn full_width_shl_and_shr_clear_destination() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0x1234_5678)],
        ),
        instr(
            Opcode::Shl,
            false,
            vec![Operand::Register(0), Operand::Immediate(32)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0x8765_4321)],
        ),
        instr(
            Opcode::Shr,
            false,
            vec![Operand::Register(1), Operand::Immediate(32)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(2), Operand::Immediate(0xff)],
        ),
        instr(
            Opcode::Shl,
            true,
            vec![Operand::Register(2), Operand::Immediate(8)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(3), Operand::Immediate(0xff)],
        ),
        instr(
            Opcode::Shr,
            true,
            vec![Operand::Register(3), Operand::Immediate(8)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0);
    assert_eq!(result.regs[1], 0);
    assert_eq!(result.regs[2] & 0xff, 0);
    assert_eq!(result.regs[3] & 0xff, 0);
}

#[test]
fn sbb_sets_borrow_flag_when_subtrahend_plus_carry_wraps_byte_width() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Cmp,
            true,
            vec![Operand::Immediate(0), Operand::Immediate(1)],
        ),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(
            Opcode::Sbb,
            true,
            vec![Operand::Register(0), Operand::Immediate(0xff)],
        ),
        instr(Opcode::Jb, false, vec![Operand::Immediate(6)]),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0xdead)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(1), Operand::Immediate(0xbeef)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0] & 0xff, 0);
    assert_eq!(result.regs[1], 0xbeef);
}

#[test]
fn zero_count_shifts_are_noops() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Register(0), Operand::Immediate(0x1234_5678)],
        ),
        instr(
            Opcode::Shl,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(
            Opcode::Shr,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(
            Opcode::Sar,
            false,
            vec![Operand::Register(0), Operand::Immediate(0)],
        ),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0x1234_5678);
}

#[test]
fn output_range_accepts_exclusive_memory_end() {
    let program = Program {
        static_data: Vec::new(),
        instructions: vec![
            instr(
                Opcode::Mov,
                false,
                vec![
                    Operand::Absolute((GLOBAL_BASE + 0x20) as u32),
                    Operand::Immediate((MEMORY_SIZE - 1) as u32),
                ],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![
                    Operand::Absolute((GLOBAL_BASE + 0x1c) as u32),
                    Operand::Immediate(1),
                ],
            ),
            instr(
                Opcode::Mov,
                true,
                vec![
                    Operand::Absolute((MEMORY_SIZE - 1) as u32),
                    Operand::Immediate(0x5a),
                ],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ],
    };

    let result = program
        .execute(Invocation {
            input: &[0],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap();

    assert_eq!(result.output, [0x5a]);
}

#[test]
fn output_range_past_memory_is_discarded() {
    let program = Program {
        static_data: Vec::new(),
        instructions: vec![
            instr(
                Opcode::Mov,
                false,
                vec![
                    Operand::Absolute((GLOBAL_BASE + 0x20) as u32),
                    Operand::Immediate((MEMORY_SIZE - 1) as u32),
                ],
            ),
            instr(
                Opcode::Mov,
                false,
                vec![
                    Operand::Absolute((GLOBAL_BASE + 0x1c) as u32),
                    Operand::Immediate(2),
                ],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ],
    };

    let result = program
        .execute(Invocation {
            input: &[0x5a],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap();
    assert!(result.output.is_empty());
}

#[test]
fn rejects_a_program_that_writes_to_an_immediate() {
    let program = Program {
        static_data: Vec::new(),
        instructions: vec![
            instr(
                Opcode::Mov,
                false,
                vec![Operand::Immediate(0), Operand::Immediate(1)],
            ),
            instr(Opcode::Ret, false, Vec::new()),
        ],
    };

    assert_eq!(
        program.execute(Invocation {
            input: &[],
            regs: [0; 7],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        }),
        Err(Error::InvalidData("RARVM write to immediate operand"))
    );
}

#[test]
fn parsed_shifts_reject_an_immediate_destination() {
    for opcode in [Opcode::Shl, Opcode::Shr, Opcode::Sar] {
        let mut bits = BitWriter::new();
        bits.write_bits(0, 1); // no static data
        write_opcode(&mut bits, opcode);
        bits.write_bits(0, 1); // word mode
        write_number_immediate(&mut bits, 1); // destination
        write_number_immediate(&mut bits, 1); // nonzero shift count
        write_opcode(&mut bits, Opcode::Ret);

        let program = Program::parse(&with_xor(bits.finish())).unwrap();
        assert_eq!(program.instructions[0].opcode, opcode);
        assert_eq!(
            program.execute(Invocation {
                input: &[],
                regs: [0; 7],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            }),
            Err(Error::InvalidData("RARVM write to immediate operand")),
            "{opcode:?} should reject an immediate destination",
        );
    }
}

#[test]
fn executes_extension_exchange_multiply_divide_and_carry_arithmetic() {
    let result = execute_instructions(vec![
        instr(
            Opcode::Mov,
            false,
            vec![Operand::Absolute(0), Operand::Immediate(0x80)],
        ),
        instr(
            Opcode::Movzx,
            false,
            vec![Operand::Register(0), Operand::Absolute(0)],
        ),
        instr(
            Opcode::Movsx,
            false,
            vec![Operand::Register(1), Operand::Absolute(0)],
        ),
        instr(
            Opcode::Xchg,
            false,
            vec![Operand::Register(0), Operand::Register(1)],
        ),
        instr(
            Opcode::Mul,
            false,
            vec![Operand::Register(1), Operand::Immediate(3)],
        ),
        instr(
            Opcode::Div,
            false,
            vec![Operand::Register(1), Operand::Immediate(2)],
        ),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(1), Operand::Immediate(2)],
        ),
        instr(
            Opcode::Adc,
            false,
            vec![Operand::Register(1), Operand::Immediate(1)],
        ),
        instr(
            Opcode::Cmp,
            false,
            vec![Operand::Immediate(1), Operand::Immediate(2)],
        ),
        instr(
            Opcode::Sbb,
            false,
            vec![Operand::Register(1), Operand::Immediate(2)],
        ),
        instr(Opcode::Print, false, Vec::new()),
        instr(Opcode::Ret, false, Vec::new()),
    ]);

    assert_eq!(result.regs[0], 0xffff_ff80);
    assert_eq!(result.regs[1], 0xbf);
}

#[test]
fn preserves_requested_user_globals() {
    let program = Program {
        static_data: b"static".to_vec(),
        instructions: vec![
            Instruction {
                opcode: Opcode::Mov,
                byte_mode: false,
                operands: vec![Operand::Absolute(0x3c030), Operand::Immediate(4)],
            },
            Instruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Vec::new(),
            },
        ],
    };

    let result = program
        .execute(Invocation {
            input: &[1, 2, 3],
            regs: [0; 7],
            global_data: &[0; 64],
            file_offset: 0x1_0000_0002,
            exec_count: 9,
        })
        .unwrap();

    assert_eq!(result.output, [1, 2, 3]);
    assert_eq!(result.globals.len(), 68);
    assert_eq!(&result.globals[64..], b"stat");
}

#[test]
fn parse_rejects_huge_static_data_size_without_preallocating() {
    let err = Program::parse(&[0xff, 0xff, 0xff, 0xff, 0, 0]).unwrap_err();
    assert_eq!(err, Error::InvalidData("RARVM static data is too large"));
}

#[test]
fn parse_rejects_static_data_larger_than_vm_memory() {
    let mut bits = BitWriter::new();
    bits.write_bits(1, 1);
    write_vm_number(&mut bits, MAX_STATIC_DATA as u32);

    let err = Program::parse(&with_xor(bits.finish())).unwrap_err();
    assert_eq!(err, Error::InvalidData("RARVM static data is too large"));
}

fn instr(opcode: Opcode, byte_mode: bool, operands: Vec<Operand>) -> Instruction {
    Instruction {
        opcode,
        byte_mode,
        operands,
    }
}

fn execute_instructions(instructions: Vec<Instruction>) -> ExecutionResult {
    Program {
        static_data: Vec::new(),
        instructions,
    }
    .execute(Invocation {
        input: &[0],
        regs: [0; 7],
        global_data: &[],
        file_offset: 0,
        exec_count: 0,
    })
    .unwrap()
}

struct BitWriter {
    output: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            if self.bit_pos.is_multiple_of(8) {
                self.output.push(0);
            }
            if (value >> i) & 1 != 0 {
                let idx = self.output.len() - 1;
                self.output[idx] |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}

fn with_xor(mut payload: Vec<u8>) -> Vec<u8> {
    let checksum = payload.iter().fold(0u8, |acc, &byte| acc ^ byte);
    payload.insert(0, checksum);
    payload
}

fn write_opcode(bits: &mut BitWriter, opcode: Opcode) {
    let value = opcode as u8;
    if value <= 7 {
        bits.write_bits(0, 1);
        bits.write_bits(u32::from(value), 3);
    } else {
        bits.write_bits(1, 1);
        bits.write_bits(u32::from(value - 8), 5);
    }
}

fn write_reg(bits: &mut BitWriter, reg: u8) {
    bits.write_bits(1, 1);
    bits.write_bits(u32::from(reg), 3);
}

fn write_number_immediate(bits: &mut BitWriter, value: u32) {
    bits.write_bits(0, 2);
    write_vm_number(bits, value);
}

fn write_byte_immediate(bits: &mut BitWriter, value: u8) {
    bits.write_bits(0, 2);
    bits.write_bits(u32::from(value), 8);
}

fn write_reg_indirect(bits: &mut BitWriter, reg: u8) {
    bits.write_bits(0b010, 3);
    bits.write_bits(u32::from(reg), 3);
}

fn write_indexed(bits: &mut BitWriter, reg: u8, base: u32) {
    bits.write_bits(0b0110, 4);
    bits.write_bits(u32::from(reg), 3);
    write_vm_number(bits, base);
}

fn write_absolute(bits: &mut BitWriter, address: u32) {
    bits.write_bits(0b0111, 4);
    write_vm_number(bits, address);
}

fn write_vm_number(bits: &mut BitWriter, value: u32) {
    if value <= 15 {
        bits.write_bits(0, 2);
        bits.write_bits(value, 4);
    } else if value <= 255 {
        bits.write_bits(1, 2);
        bits.write_bits(value, 8);
    } else if value <= 0xffff {
        bits.write_bits(2, 2);
        bits.write_bits(value, 16);
    } else {
        bits.write_bits(3, 2);
        bits.write_bits(value, 32);
    }
}
