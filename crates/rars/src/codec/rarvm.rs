use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};

const MEMORY_SIZE: usize = 0x40000;
const MEMORY_MASK: u32 = 0x3ffff;
const GLOBAL_BASE: usize = 0x3c000;
const SYSTEM_GLOBAL_SIZE: usize = 64;
const MAX_USER_GLOBAL: usize = 0x2000 - SYSTEM_GLOBAL_SIZE;
const MAX_STATIC_DATA: usize = MEMORY_SIZE - GLOBAL_BASE;
const MAX_INSTRUCTIONS: usize = 25_000_000;
const FLAG_C: u32 = 1;
const FLAG_Z: u32 = 2;
const FLAG_S: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub static_data: Vec<u8>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub byte_mode: bool,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Mov = 0,
    Cmp = 1,
    Add = 2,
    Sub = 3,
    Jz = 4,
    Jnz = 5,
    Inc = 6,
    Dec = 7,
    Jmp = 8,
    Xor = 9,
    And = 10,
    Or = 11,
    Test = 12,
    Js = 13,
    Jns = 14,
    Jb = 15,
    Jbe = 16,
    Ja = 17,
    Jae = 18,
    Push = 19,
    Pop = 20,
    Call = 21,
    Ret = 22,
    Not = 23,
    Shl = 24,
    Shr = 25,
    Sar = 26,
    Neg = 27,
    Pusha = 28,
    Popa = 29,
    Pushf = 30,
    Popf = 31,
    Movzx = 32,
    Movsx = 33,
    Xchg = 34,
    Mul = 35,
    Div = 36,
    Adc = 37,
    Sbb = 38,
    Print = 39,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Register(u8),
    Immediate(u32),
    RegisterIndirect(u8),
    Indexed { register: u8, base: u32 },
    Absolute(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation<'a> {
    pub input: &'a [u8],
    pub regs: [u32; 7],
    pub global_data: &'a [u8],
    pub file_offset: u64,
    pub exec_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub output: Vec<u8>,
    pub globals: Vec<u8>,
    pub regs: [u32; 8],
}

impl Program {
    pub fn parse(blob: &[u8]) -> Result<Self> {
        OwnedProgram::parse(blob, &Allowance::default()).map(OwnedProgram::into_public)
    }

    pub fn execute(&self, invocation: Invocation<'_>) -> Result<ExecutionResult> {
        self.execute_with_control(invocation, &crate::read_control::ReadControl::default())
    }

    pub(crate) fn execute_with_control(
        &self,
        invocation: Invocation<'_>,
        control: &crate::read_control::ReadControl,
    ) -> Result<ExecutionResult> {
        control.check_codec()?;
        let mut vm = Vm::with_allowance(self, invocation, &Allowance::default())?;
        vm.run(self, control).map(OwnedExecutionResult::into_public)
    }
}

#[derive(Debug)]
pub(crate) struct OwnedProgram<B: Budget> {
    static_data: Buffer<u8, B>,
    instructions: Buffer<OwnedInstruction<B>, B>,
}
#[derive(Debug)]
struct OwnedInstruction<B: Budget> {
    opcode: Opcode,
    byte_mode: bool,
    operands: Buffer<Operand, B>,
}
impl<B: Budget> OwnedProgram<B> {
    pub(crate) fn try_clone(&self) -> Result<Self> {
        let allowance = self.static_data.allowance();
        Ok(Self {
            static_data: Buffer::copied(&self.static_data, &allowance)?,
            instructions: Buffer::try_collect(
                self.instructions.iter().map(|instruction| {
                    Ok(OwnedInstruction {
                        opcode: instruction.opcode,
                        byte_mode: instruction.byte_mode,
                        operands: Buffer::copied(&instruction.operands, &allowance)?,
                    })
                }),
                &allowance,
            )?,
        })
    }
    pub(crate) fn execute_with_control(
        &self,
        invocation: Invocation<'_>,
        control: &crate::read_control::ReadControl,
    ) -> Result<OwnedExecutionResult<B>> {
        control.check_codec()?;
        let mut vm = Vm::with_allowance(self, invocation, &self.static_data.allowance())?;
        vm.run(self, control)
    }
    pub(crate) fn parse(blob: &[u8], allowance: &B) -> Result<Self> {
        if blob.is_empty() {
            return Err(Error::InvalidData("RARVM program blob is empty"));
        }
        if blob.iter().fold(0u8, |acc, &byte| acc ^ byte) != 0 {
            return Err(Error::InvalidData("RARVM program checksum mismatch"));
        }

        let mut bits = BitReader::new(&blob[1..]);
        let mut static_data = Buffer::new(allowance);
        if bits.read_bit()? != 0 {
            let size = bits
                .read_vm_number()?
                .checked_add(1)
                .ok_or(Error::InvalidData("RARVM static data size overflows"))?
                as usize;
            if size > MAX_STATIC_DATA {
                return Err(Error::InvalidData("RARVM static data is too large"));
            }
            static_data = Buffer::with_capacity(size, allowance)?;
            for _ in 0..size {
                static_data.push_admitted(bits.read_bits(8)? as u8);
            }
        }

        let mut instructions = Buffer::new(allowance);
        while bits.remaining_bits() >= 8 {
            match parse_instruction_with_allowance(&mut bits, instructions.len(), allowance) {
                Ok(instruction) => instructions.try_push(instruction)?,
                // Instruction decoding only performs bounded bit reads. An
                // incomplete final instruction is ignored for compatibility.
                Err(Error::NeedMoreInput | Error::InvalidData(_)) => break,
                Err(error) => return Err(error),
            }
        }

        if instructions
            .last()
            .is_none_or(|instruction| !instruction.opcode.is_unconditional_control_transfer())
        {
            instructions.try_push(OwnedInstruction {
                opcode: Opcode::Ret,
                byte_mode: false,
                operands: Buffer::new(allowance),
            })?;
        }

        Ok(Self {
            static_data,
            instructions,
        })
    }
}
#[cfg(test)]
impl From<Program> for OwnedProgram<Allowance> {
    fn from(program: Program) -> Self {
        Self {
            static_data: program.static_data.into(),
            instructions: program
                .instructions
                .into_iter()
                .map(|instruction| OwnedInstruction {
                    opcode: instruction.opcode,
                    byte_mode: instruction.byte_mode,
                    operands: instruction.operands.into(),
                })
                .collect::<Vec<_>>()
                .into(),
        }
    }
}
impl OwnedProgram<Allowance> {
    fn into_public(self) -> Program {
        Program {
            static_data: self.static_data.into_vec(),
            instructions: self
                .instructions
                .into_vec()
                .into_iter()
                .map(|instruction| Instruction {
                    opcode: instruction.opcode,
                    byte_mode: instruction.byte_mode,
                    operands: instruction.operands.into_vec(),
                })
                .collect(),
        }
    }
}
struct InstructionRef<'a> {
    opcode: Opcode,
    byte_mode: bool,
    operands: &'a [Operand],
}
trait ProgramCode {
    fn static_data(&self) -> &[u8];
    fn instruction(&self, index: usize) -> Option<InstructionRef<'_>>;
    fn instruction_count(&self) -> usize;
}
impl ProgramCode for Program {
    fn static_data(&self) -> &[u8] {
        &self.static_data
    }
    fn instruction(&self, index: usize) -> Option<InstructionRef<'_>> {
        self.instructions
            .get(index)
            .map(|instruction| InstructionRef {
                opcode: instruction.opcode,
                byte_mode: instruction.byte_mode,
                operands: &instruction.operands,
            })
    }
    fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}
impl<B: Budget> ProgramCode for OwnedProgram<B> {
    fn static_data(&self) -> &[u8] {
        &self.static_data
    }
    fn instruction(&self, index: usize) -> Option<InstructionRef<'_>> {
        self.instructions
            .get(index)
            .map(|instruction| InstructionRef {
                opcode: instruction.opcode,
                byte_mode: instruction.byte_mode,
                operands: &instruction.operands,
            })
    }
    fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}
#[derive(Debug)]
pub(crate) struct OwnedExecutionResult<B: Budget> {
    pub(crate) output: Buffer<u8, B>,
    pub(crate) globals: Buffer<u8, B>,
    pub(crate) regs: [u32; 8],
}
impl OwnedExecutionResult<Allowance> {
    fn into_public(self) -> ExecutionResult {
        ExecutionResult {
            output: self.output.into_vec(),
            globals: self.globals.into_vec(),
            regs: self.regs,
        }
    }
}

impl Opcode {
    fn from_encoded(value: u8) -> Self {
        const OPCODES: [Opcode; 40] = [
            Opcode::Mov,
            Opcode::Cmp,
            Opcode::Add,
            Opcode::Sub,
            Opcode::Jz,
            Opcode::Jnz,
            Opcode::Inc,
            Opcode::Dec,
            Opcode::Jmp,
            Opcode::Xor,
            Opcode::And,
            Opcode::Or,
            Opcode::Test,
            Opcode::Js,
            Opcode::Jns,
            Opcode::Jb,
            Opcode::Jbe,
            Opcode::Ja,
            Opcode::Jae,
            Opcode::Push,
            Opcode::Pop,
            Opcode::Call,
            Opcode::Ret,
            Opcode::Not,
            Opcode::Shl,
            Opcode::Shr,
            Opcode::Sar,
            Opcode::Neg,
            Opcode::Pusha,
            Opcode::Popa,
            Opcode::Pushf,
            Opcode::Popf,
            Opcode::Movzx,
            Opcode::Movsx,
            Opcode::Xchg,
            Opcode::Mul,
            Opcode::Div,
            Opcode::Adc,
            Opcode::Sbb,
            Opcode::Print,
        ];
        // The short form is three bits and the long form is five bits plus
        // eight, so the wire representation can only produce 0..=39.
        OPCODES[usize::from(value)]
    }

    fn operand_count(self) -> usize {
        match self {
            Self::Ret | Self::Pusha | Self::Popa | Self::Pushf | Self::Popf | Self::Print => 0,
            Self::Jz
            | Self::Jnz
            | Self::Inc
            | Self::Dec
            | Self::Jmp
            | Self::Js
            | Self::Jns
            | Self::Jb
            | Self::Jbe
            | Self::Ja
            | Self::Jae
            | Self::Push
            | Self::Pop
            | Self::Call
            | Self::Not
            | Self::Neg => 1,
            Self::Mov
            | Self::Cmp
            | Self::Add
            | Self::Sub
            | Self::Xor
            | Self::And
            | Self::Or
            | Self::Test
            | Self::Shl
            | Self::Shr
            | Self::Sar
            | Self::Movzx
            | Self::Movsx
            | Self::Xchg
            | Self::Mul
            | Self::Div
            | Self::Adc
            | Self::Sbb => 2,
        }
    }

    fn supports_byte_mode(self) -> bool {
        matches!(
            self,
            Self::Mov
                | Self::Cmp
                | Self::Add
                | Self::Sub
                | Self::Inc
                | Self::Dec
                | Self::Xor
                | Self::And
                | Self::Or
                | Self::Test
                | Self::Not
                | Self::Shl
                | Self::Shr
                | Self::Sar
                | Self::Neg
                | Self::Xchg
                | Self::Mul
                | Self::Div
                | Self::Adc
                | Self::Sbb
        )
    }

    fn is_jump_or_call(self) -> bool {
        matches!(
            self,
            Self::Jz
                | Self::Jnz
                | Self::Jmp
                | Self::Js
                | Self::Jns
                | Self::Jb
                | Self::Jbe
                | Self::Ja
                | Self::Jae
                | Self::Call
        )
    }

    fn is_unconditional_control_transfer(self) -> bool {
        matches!(self, Self::Jmp | Self::Ret)
    }
}

fn parse_instruction_with_allowance<B: Budget>(
    bits: &mut BitReader<'_>,
    instruction_index: usize,
    allowance: &B,
) -> Result<OwnedInstruction<B>> {
    let opcode = if bits.read_bit()? == 0 {
        Opcode::from_encoded(bits.read_bits(3)? as u8)
    } else {
        Opcode::from_encoded(bits.read_bits(5)? as u8 + 8)
    };
    let byte_mode = opcode.supports_byte_mode() && bits.read_bit()? != 0;
    let mut operands = Buffer::with_capacity(opcode.operand_count(), allowance)?;
    for operand_index in 0..opcode.operand_count() {
        let mut operand = parse_operand(bits, byte_mode)?;
        if operand_index == 0 && opcode.is_jump_or_call() {
            if let Operand::Immediate(value) = operand {
                operand = Operand::Immediate(remap_jump_target(value, instruction_index));
            }
        }
        operands.push_admitted(operand);
    }
    Ok(OwnedInstruction {
        opcode,
        byte_mode,
        operands,
    })
}

fn parse_operand(bits: &mut BitReader<'_>, byte_mode: bool) -> Result<Operand> {
    if bits.read_bit()? != 0 {
        return Ok(Operand::Register(bits.read_bits(3)? as u8));
    }
    if bits.read_bit()? == 0 {
        return if byte_mode {
            Ok(Operand::Immediate(bits.read_bits(8)?))
        } else {
            Ok(Operand::Immediate(bits.read_vm_number()?))
        };
    }
    if bits.read_bit()? == 0 {
        return Ok(Operand::RegisterIndirect(bits.read_bits(3)? as u8));
    }
    if bits.read_bit()? == 0 {
        Ok(Operand::Indexed {
            register: bits.read_bits(3)? as u8,
            base: bits.read_vm_number()?,
        })
    } else {
        Ok(Operand::Absolute(bits.read_vm_number()?))
    }
}

fn remap_jump_target(value: u32, instruction_index: usize) -> u32 {
    if value >= 256 {
        return value - 256;
    }

    let mut distance = value as i64;
    if distance >= 136 {
        distance -= 264;
    } else if distance >= 16 {
        distance -= 8;
    } else if distance >= 8 {
        distance -= 16;
    }
    (instruction_index as i64).wrapping_add(distance) as u32
}

struct Vm<B: Budget = Allowance> {
    memory: Buffer<u8, B>,
    regs: [u32; 8],
    flags: u32,
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Left,
    Right,
    ArithmeticRight,
}

impl<B: Budget> Vm<B> {
    fn with_allowance(
        program: &impl ProgramCode,
        invocation: Invocation<'_>,
        allowance: &B,
    ) -> Result<Self> {
        if invocation.input.len() > GLOBAL_BASE {
            return Err(Error::InvalidData("RARVM filter input is too large"));
        }

        let mut memory = Buffer::filled(MEMORY_SIZE, 0, allowance)?;
        memory[..invocation.input.len()].copy_from_slice(invocation.input);
        let global_len = invocation.global_data.len().min(0x2000);
        memory[GLOBAL_BASE..GLOBAL_BASE + global_len]
            .copy_from_slice(&invocation.global_data[..global_len]);
        let static_start = GLOBAL_BASE + global_len;
        let static_len = program
            .static_data()
            .len()
            .min(MEMORY_SIZE.saturating_sub(static_start));
        memory[static_start..static_start + static_len]
            .copy_from_slice(&program.static_data()[..static_len]);

        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x1c,
            invocation.input.len() as u32,
        );
        write_u32(&mut memory, GLOBAL_BASE + 0x20, 0);
        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x24,
            invocation.file_offset as u32,
        );
        write_u32(
            &mut memory,
            GLOBAL_BASE + 0x28,
            (invocation.file_offset >> 32) as u32,
        );
        write_u32(&mut memory, GLOBAL_BASE + 0x2c, invocation.exec_count);

        let mut regs = [0u32; 8];
        regs[..7].copy_from_slice(&invocation.regs);
        regs[3] = GLOBAL_BASE as u32;
        regs[4] = invocation.input.len() as u32;
        regs[5] = invocation.exec_count;
        regs[6] = invocation.file_offset as u32;
        regs[7] = MEMORY_SIZE as u32;

        Ok(Self {
            memory,
            regs,
            flags: 0,
        })
    }

    fn run(
        &mut self,
        program: &impl ProgramCode,
        control: &crate::read_control::ReadControl,
    ) -> Result<OwnedExecutionResult<B>> {
        self.run_with_limit(program, control, MAX_INSTRUCTIONS)
    }

    fn run_with_limit(
        &mut self,
        program: &impl ProgramCode,
        control: &crate::read_control::ReadControl,
        instruction_limit: usize,
    ) -> Result<OwnedExecutionResult<B>> {
        let mut poller = control.poller();
        let mut ip = 0usize;
        let mut terminated = false;
        for _ in 0..instruction_limit {
            poller.check_codec(0)?;
            let Some(instruction) = program.instruction(ip) else {
                terminated = true;
                break;
            };
            ip += 1;
            if let Some(next_ip) = self.execute_instruction(&instruction, ip)? {
                if next_ip >= program.instruction_count() {
                    terminated = true;
                    break;
                }
                ip = next_ip;
            }
            if instruction.opcode == Opcode::Ret && self.regs[7] >= MEMORY_SIZE as u32 {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(Error::InvalidData("RARVM instruction limit exceeded"));
        }

        let mut output_pos = self.read_u32(GLOBAL_BASE + 0x20) as usize & MEMORY_MASK as usize;
        let mut output_size = self.read_u32(GLOBAL_BASE + 0x1c) as usize & MEMORY_MASK as usize;
        if output_pos
            .checked_add(output_size)
            .is_none_or(|end| end > MEMORY_SIZE)
        {
            output_pos = 0;
            output_size = 0;
        }
        let output = Buffer::copied(
            &self.memory[output_pos..output_pos + output_size],
            &self.memory.allowance(),
        )?;

        let user_global = (self.read_u32(GLOBAL_BASE + 0x30) as usize).min(MAX_USER_GLOBAL);
        let globals = Buffer::copied(
            &self.memory[GLOBAL_BASE..GLOBAL_BASE + SYSTEM_GLOBAL_SIZE + user_global],
            &self.memory.allowance(),
        )?;
        Ok(OwnedExecutionResult {
            output,
            globals,
            regs: self.regs,
        })
    }

    fn execute_instruction(
        &mut self,
        instruction: &InstructionRef<'_>,
        ip: usize,
    ) -> Result<Option<usize>> {
        let byte_mode = instruction.byte_mode;
        let op = |index| {
            instruction
                .operands
                .get(index)
                .ok_or(Error::InvalidData("RARVM instruction operand is missing"))
        };
        match instruction.opcode {
            Opcode::Mov => {
                let value = self.read_operand(op(1)?, byte_mode);
                self.write_operand(op(0)?, value, byte_mode)?;
            }
            Opcode::Cmp => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                self.set_sub_flags(a, b, 0, byte_mode);
            }
            Opcode::Add => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = self.mask_width(a.wrapping_add(b), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_add_flags(a, b, 0, result, byte_mode);
            }
            Opcode::Sub => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = self.mask_width(a.wrapping_sub(b), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_sub_flags(a, b, 0, byte_mode);
            }
            Opcode::Jz => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_Z != 0)),
            Opcode::Jnz => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_Z == 0)),
            Opcode::Inc => {
                let value = self.read_operand(op(0)?, byte_mode).wrapping_add(1);
                let result = self.mask_width(value, byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_zs(result, byte_mode);
            }
            Opcode::Dec => {
                let value = self.read_operand(op(0)?, byte_mode).wrapping_sub(1);
                let result = self.mask_width(value, byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                self.set_zs(result, byte_mode);
            }
            Opcode::Jmp => return Ok(Some(self.read_operand(op(0)?, false) as usize)),
            Opcode::Xor | Opcode::And | Opcode::Or | Opcode::Test => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let result = if instruction.opcode == Opcode::Xor {
                    a ^ b
                } else if instruction.opcode == Opcode::Or {
                    a | b
                } else {
                    a & b
                };
                let result = self.mask_width(result, byte_mode);
                if instruction.opcode != Opcode::Test {
                    self.write_operand(op(0)?, result, byte_mode)?;
                }
                self.set_zs(result, byte_mode);
            }
            Opcode::Js => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_S != 0)),
            Opcode::Jns => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_S == 0)),
            Opcode::Jb => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_C != 0)),
            Opcode::Jbe => {
                return Ok(self.conditional_jump(op(0)?, self.flags & (FLAG_C | FLAG_Z) != 0));
            }
            Opcode::Ja => {
                return Ok(self.conditional_jump(op(0)?, self.flags & (FLAG_C | FLAG_Z) == 0));
            }
            Opcode::Jae => return Ok(self.conditional_jump(op(0)?, self.flags & FLAG_C == 0)),
            Opcode::Push => self.push(self.read_operand(op(0)?, false)),
            Opcode::Pop => {
                let value = self.pop();
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Call => {
                self.push(ip as u32);
                return Ok(Some(self.read_operand(op(0)?, false) as usize));
            }
            Opcode::Ret => {
                if self.regs[7] >= MEMORY_SIZE as u32 {
                    return Ok(Some(usize::MAX));
                }
                return Ok(Some(self.pop() as usize));
            }
            Opcode::Not => {
                let result = self.mask_width(!self.read_operand(op(0)?, byte_mode), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
            }
            Opcode::Shl => {
                self.shift(
                    ShiftKind::Left,
                    op(0)?,
                    self.read_operand(op(1)?, byte_mode),
                    byte_mode,
                )?;
            }
            Opcode::Shr => {
                self.shift(
                    ShiftKind::Right,
                    op(0)?,
                    self.read_operand(op(1)?, byte_mode),
                    byte_mode,
                )?;
            }
            Opcode::Sar => {
                self.shift(
                    ShiftKind::ArithmeticRight,
                    op(0)?,
                    self.read_operand(op(1)?, byte_mode),
                    byte_mode,
                )?;
            }
            Opcode::Neg => {
                let value = self.read_operand(op(0)?, byte_mode);
                let result = self.mask_width(0u32.wrapping_sub(value), byte_mode);
                self.write_operand(op(0)?, result, byte_mode)?;
                if result == 0 {
                    self.flags = FLAG_Z;
                } else {
                    self.flags = FLAG_C | (result & self.sign_bit(byte_mode));
                }
            }
            Opcode::Pusha => {
                let regs = self.regs;
                for value in regs {
                    self.push(value);
                }
            }
            Opcode::Popa => {
                let mut stack = self.regs[7];
                for index in (0..8).rev() {
                    self.regs[index] = self.read_mem(stack, false);
                    stack = stack.wrapping_add(4);
                }
            }
            Opcode::Pushf => self.push(self.flags),
            Opcode::Popf => self.flags = self.pop(),
            Opcode::Movzx => {
                let value = self.read_operand(op(1)?, true) & 0xff;
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Movsx => {
                let value = self.read_operand(op(1)?, true) as u8 as i8 as i32 as u32;
                self.write_operand(op(0)?, value, false)?;
            }
            Opcode::Xchg => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                self.write_operand(op(0)?, b, byte_mode)?;
                self.write_operand(op(1)?, a, byte_mode)?;
            }
            Opcode::Mul => {
                let result = self
                    .read_operand(op(0)?, byte_mode)
                    .wrapping_mul(self.read_operand(op(1)?, byte_mode));
                self.write_operand(op(0)?, self.mask_width(result, byte_mode), byte_mode)?;
            }
            Opcode::Div => {
                let divisor = self.read_operand(op(1)?, byte_mode);
                if let Some(result) = self.read_operand(op(0)?, byte_mode).checked_div(divisor) {
                    self.write_operand(op(0)?, result, byte_mode)?;
                }
            }
            Opcode::Adc | Opcode::Sbb => {
                let a = self.read_operand(op(0)?, byte_mode);
                let b = self.read_operand(op(1)?, byte_mode);
                let carry = u32::from(self.flags & FLAG_C != 0);
                let result = if instruction.opcode == Opcode::Adc {
                    self.mask_width(a.wrapping_add(b).wrapping_add(carry), byte_mode)
                } else {
                    self.mask_width(a.wrapping_sub(b).wrapping_sub(carry), byte_mode)
                };
                self.write_operand(op(0)?, result, byte_mode)?;
                if instruction.opcode == Opcode::Adc {
                    self.set_add_flags(a, b, carry, result, byte_mode);
                } else {
                    self.set_sub_flags(a, b, carry, byte_mode);
                }
            }
            Opcode::Print => {}
        }
        Ok(None)
    }

    fn conditional_jump(&self, operand: &Operand, condition: bool) -> Option<usize> {
        condition.then_some(self.read_operand(operand, false) as usize)
    }

    fn read_operand(&self, operand: &Operand, byte_mode: bool) -> u32 {
        match *operand {
            Operand::Register(index) => {
                let value = self.regs[index as usize];
                if byte_mode {
                    value & 0xff
                } else {
                    value
                }
            }
            Operand::Immediate(value) => self.mask_width(value, byte_mode),
            Operand::RegisterIndirect(index) => self.read_mem(self.regs[index as usize], byte_mode),
            Operand::Indexed { register, base } => {
                self.read_mem(base.wrapping_add(self.regs[register as usize]), byte_mode)
            }
            Operand::Absolute(address) => self.read_mem(address, byte_mode),
        }
    }

    fn write_operand(&mut self, operand: &Operand, value: u32, byte_mode: bool) -> Result<()> {
        match *operand {
            Operand::Register(index) => {
                let slot = &mut self.regs[index as usize];
                if byte_mode {
                    *slot = (*slot & 0xffff_ff00) | (value & 0xff);
                } else {
                    *slot = value;
                }
            }
            Operand::RegisterIndirect(index) => {
                self.write_mem(self.regs[index as usize], value, byte_mode)
            }
            Operand::Indexed { register, base } => {
                self.write_mem(
                    base.wrapping_add(self.regs[register as usize]),
                    value,
                    byte_mode,
                );
            }
            Operand::Absolute(address) => self.write_mem(address, value, byte_mode),
            Operand::Immediate(_) => {
                return Err(Error::InvalidData("RARVM write to immediate operand"))
            }
        }
        Ok(())
    }

    fn read_mem(&self, address: u32, byte_mode: bool) -> u32 {
        let address = address & MEMORY_MASK;
        if byte_mode {
            u32::from(self.memory[address as usize])
        } else {
            self.read_u32(address as usize)
        }
    }

    fn write_mem(&mut self, address: u32, value: u32, byte_mode: bool) {
        let address = address & MEMORY_MASK;
        if byte_mode {
            self.memory[address as usize] = value as u8;
        } else {
            write_u32(&mut self.memory, address as usize, value);
        }
    }

    fn read_u32(&self, address: usize) -> u32 {
        let address = address as u32;
        u32::from_le_bytes([
            self.memory[(address & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(1) & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(2) & MEMORY_MASK) as usize],
            self.memory[(address.wrapping_add(3) & MEMORY_MASK) as usize],
        ])
    }

    fn push(&mut self, value: u32) {
        self.regs[7] = self.regs[7].wrapping_sub(4);
        self.write_mem(self.regs[7], value, false);
    }

    fn pop(&mut self) -> u32 {
        let value = self.read_mem(self.regs[7], false);
        self.regs[7] = self.regs[7].wrapping_add(4);
        value
    }

    fn shift(&mut self, kind: ShiftKind, dst: &Operand, count: u32, byte_mode: bool) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let width = if byte_mode { 8 } else { 32 };
        let count = count.min(width);
        let value = self.read_operand(dst, byte_mode);
        let result = match kind {
            ShiftKind::Left => {
                if count == width {
                    0
                } else {
                    value.wrapping_shl(count)
                }
            }
            ShiftKind::Right => {
                if count == width {
                    0
                } else {
                    value.wrapping_shr(count)
                }
            }
            ShiftKind::ArithmeticRight => {
                if byte_mode {
                    if count >= 8 {
                        if value & 0x80 != 0 {
                            0xff
                        } else {
                            0
                        }
                    } else {
                        ((value as u8 as i8) >> count) as u8 as u32
                    }
                } else if count >= 32 {
                    if value & 0x8000_0000 != 0 {
                        u32::MAX
                    } else {
                        0
                    }
                } else {
                    ((value as i32) >> count) as u32
                }
            }
        };
        let carry = match kind {
            ShiftKind::Left => value & (1 << (width - count)) != 0,
            ShiftKind::Right | ShiftKind::ArithmeticRight => value & (1 << (count - 1)) != 0,
        };
        let result = self.mask_width(result, byte_mode);
        self.write_operand(dst, result, byte_mode)?;
        self.set_zsc(result, carry, byte_mode);
        Ok(())
    }

    fn set_add_flags(&mut self, a: u32, b: u32, carry: u32, result: u32, byte_mode: bool) {
        let mask = self.value_mask(byte_mode) as u64;
        let sum = (a as u64 & mask) + (b as u64 & mask) + u64::from(carry);
        self.set_zsc(result, sum > mask, byte_mode);
    }

    fn set_sub_flags(&mut self, a: u32, b: u32, borrow: u32, byte_mode: bool) {
        let mask = self.value_mask(byte_mode) as u64;
        let a = a as u64 & mask;
        let subtrahend = (b as u64 & mask) + u64::from(borrow);
        let result = self.mask_width((a as u32).wrapping_sub(subtrahend as u32), byte_mode);
        self.set_zsc(result, a < subtrahend, byte_mode);
    }

    fn set_zs(&mut self, result: u32, byte_mode: bool) {
        self.flags = if result == 0 {
            FLAG_Z
        } else {
            result & self.sign_bit(byte_mode)
        };
    }

    fn set_zsc(&mut self, result: u32, carry: bool, byte_mode: bool) {
        self.set_zs(result, byte_mode);
        if carry {
            self.flags |= FLAG_C;
        }
    }

    fn mask_width(&self, value: u32, byte_mode: bool) -> u32 {
        value & self.value_mask(byte_mode)
    }

    fn value_mask(&self, byte_mode: bool) -> u32 {
        if byte_mode {
            0xff
        } else {
            u32::MAX
        }
    }

    fn sign_bit(&self, byte_mode: bool) -> u32 {
        if byte_mode {
            0x80
        } else {
            FLAG_S
        }
    }
}

fn write_u32(memory: &mut [u8], address: usize, value: u32) {
    let address = address as u32;
    for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
        memory[(address.wrapping_add(offset as u32) & MEMORY_MASK) as usize] = byte;
    }
}

#[cfg(test)]
impl Vm<Allowance> {
    fn new(program: &impl ProgramCode, invocation: Invocation<'_>) -> Result<Self> {
        Self::with_allowance(program, invocation, &Allowance::default())
    }
}

#[derive(Debug, Clone)]
struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    fn remaining_bits(&self) -> usize {
        self.input.len() * 8 - self.bit_pos
    }

    fn read_bit(&mut self) -> Result<u32> {
        self.read_bits(1)
    }

    fn read_bits(&mut self, count: usize) -> Result<u32> {
        if self.remaining_bits() < count {
            return Err(Error::NeedMoreInput);
        }
        let mut value = 0;
        for _ in 0..count {
            let byte = self.input[self.bit_pos / 8];
            let bit = (byte >> (7 - (self.bit_pos % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }

    fn read_vm_number(&mut self) -> Result<u32> {
        match self.read_bits(2)? {
            0 => self.read_bits(4),
            1 => {
                let high = self.read_bits(8)?;
                if high >= 16 {
                    Ok(high)
                } else {
                    Ok(0xffff_ff00 | (high << 4) | self.read_bits(4)?)
                }
            }
            2 => self.read_bits(16),
            _ => self.read_bits(32),
        }
    }
}

#[cfg(test)]
mod tests;
