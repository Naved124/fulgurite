// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! x86 and x86-64 for Fulgurite.
//!
//! Decoding and text formatting come from `iced-x86` (design §22.4: re-deriving
//! x86 decoding gains nothing). This crate turns iced's instruction into the
//! neutral [`Insn`] and its formatter output into typed [`Token`]s, and fixes the
//! formatting options so Intel syntax reads like `objdump -M intel`. The lifter
//! (M2) will live here too.

#![forbid(unsafe_code)]

use fg_core::{ArchId, Va};
use fg_ir::{
    Access, Addr, Arch, BinOp, Cond, DecodeError, Effect, Flags, Flow, Index, Insn, MemRef, Mode,
    Reg, RegPart, Syntax, Token, TokenKind, Value,
};
use iced_x86::{
    ConditionCode, Decoder, DecoderError, DecoderOptions, FlowControl, Formatter, FormatterOutput,
    FormatterTextKind, GasFormatter, Instruction, InstructionInfoFactory, InstructionInfoOptions,
    IntelFormatter, MemorySizeOptions, Mnemonic, NumberKind, OpAccess, OpKind, Register,
};
use std::cell::RefCell;

/// Longest valid x86 instruction; anything longer raises `#UD`.
pub const MAX_INSN_LEN: usize = 15;

/// Decoder options. MPX is on so the `bnd` prefix (F2 before branches, still
/// emitted in older PLT stubs) is shown as hardware decodes it.
const DECODER_OPTIONS: u32 = DecoderOptions::MPX;

/// The x86 architecture module: 32-bit (`ArchId::X86`) or 64-bit (`ArchId::X86_64`)
/// by default, any mode on request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86 {
    id: ArchId,
}

/// The x86-64 module.
pub static X86_64: X86 = X86 { id: ArchId::X86_64 };

/// The 32-bit x86 module.
pub static X86_32: X86 = X86 { id: ArchId::X86 };

impl X86 {
    /// The module for `id`, if it is an x86 architecture.
    pub fn for_arch(id: ArchId) -> Option<&'static X86> {
        match id {
            ArchId::X86_64 => Some(&X86_64),
            ArchId::X86 => Some(&X86_32),
            _ => None,
        }
    }

    fn bitness(&self, mode: Mode) -> Option<u32> {
        match mode {
            Mode::Native if self.id == ArchId::X86_64 => Some(64),
            Mode::Native => Some(32),
            Mode::X86_16 => Some(16),
            Mode::X86_32 => Some(32),
            Mode::X86_64 => Some(64),
            _ => None,
        }
    }

    fn mode_of(bitness: u32) -> Mode {
        match bitness {
            16 => Mode::X86_16,
            32 => Mode::X86_32,
            _ => Mode::X86_64,
        }
    }

    /// Decodes into an iced instruction (shared by `decode` and `format`).
    fn decode_raw(
        &self,
        bytes: &[u8],
        va: Va,
        mode: Mode,
    ) -> Result<(Instruction, u32), DecodeError> {
        let bitness = self.bitness(mode).ok_or(DecodeError::UnsupportedMode)?;
        let bytes = &bytes[..bytes.len().min(MAX_INSN_LEN)];
        if bytes.is_empty() {
            return Err(DecodeError::Truncated);
        }
        let mut decoder = Decoder::with_ip(bitness, bytes, va.0, DECODER_OPTIONS);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        match decoder.last_error() {
            DecoderError::None => Ok((instr, bitness)),
            DecoderError::NoMoreBytes => Err(Self::why_short(bytes, va, bitness)),
            _ => Err(DecodeError::Invalid {
                len: instr.len().clamp(1, MAX_INSN_LEN) as u8,
            }),
        }
    }

    /// iced may ask for more bytes before it rejects an opcode (`06` in 64-bit
    /// mode at the end of a section). Decoding again with zero padding tells a
    /// cut-off instruction from an invalid one.
    fn why_short(bytes: &[u8], va: Va, bitness: u32) -> DecodeError {
        let mut padded = [0u8; MAX_INSN_LEN];
        padded[..bytes.len()].copy_from_slice(bytes);
        let mut decoder = Decoder::with_ip(bitness, &padded, va.0, DECODER_OPTIONS);
        let instr = decoder.decode();
        match decoder.last_error() {
            DecoderError::None if instr.len() > bytes.len() => DecodeError::Truncated,
            DecoderError::None | DecoderError::NoMoreBytes => DecodeError::Truncated,
            _ => DecodeError::Invalid {
                len: instr.len().clamp(1, bytes.len()) as u8,
            },
        }
    }
}

impl Arch for X86 {
    fn id(&self) -> ArchId {
        self.id
    }

    fn max_insn_len(&self) -> usize {
        MAX_INSN_LEN
    }

    fn insn_alignment(&self) -> u64 {
        1
    }

    fn decode(&self, bytes: &[u8], va: Va, mode: Mode) -> Result<Insn, DecodeError> {
        let (instr, bitness) = self.decode_raw(bytes, va, mode)?;
        Ok(Insn::new(
            va,
            &bytes[..instr.len()],
            Self::mode_of(bitness),
            flow(&instr),
            mem_ref(&instr),
            immediate(&instr),
            instr.mnemonic() == Mnemonic::Nop,
        ))
    }

    fn format(&self, insn: &Insn, syntax: Syntax) -> Vec<Token> {
        let Ok((instr, _)) = self.decode_raw(insn.bytes.as_slice(), insn.va, insn.mode) else {
            return vec![Token::new(TokenKind::Mnemonic, "(bad)")];
        };
        let mut out = Tokens::default();
        match syntax {
            Syntax::Att => GAS.with(|f| f.borrow_mut().format(&instr, &mut out)),
            _ => INTEL.with(|f| f.borrow_mut().format(&instr, &mut out)),
        }
        drop_shadowed_prefixes(&mut out.0);
        if syntax != Syntax::Att {
            far_pointer(&mut out.0, &instr);
        }
        out.0
    }

    fn effect(&self, insn: &Insn) -> Effect {
        let Ok((instr, bitness)) = self.decode_raw(insn.bytes.as_slice(), insn.va, insn.mode)
        else {
            return Effect::UNKNOWN;
        };
        match instr.flow_control() {
            FlowControl::Next | FlowControl::ConditionalBranch => {
                known_effect(&instr, bitness).unwrap_or_else(|| other_effect(&instr))
            }
            // A direct jump changes no register (`jmp` with a far pointer
            // loads `cs`, which is not followed).
            FlowControl::UnconditionalBranch => Effect::Other {
                writes: Vec::new(),
                all: false,
                flags: false,
            },
            FlowControl::IndirectBranch => match value(&instr, 0, bitness, bitness) {
                Some(target) => Effect::Jump { target },
                None => Effect::UNKNOWN,
            },
            FlowControl::IndirectCall => match value(&instr, 0, bitness, bitness) {
                Some(target) => Effect::Call { target },
                None => Effect::UNKNOWN,
            },
            _ => Effect::UNKNOWN,
        }
    }

    fn callee_saved(&self, windows: bool) -> Vec<Reg> {
        let mut regs = vec![Register::RBX, Register::RBP, Register::RSP];
        if self.id == ArchId::X86_64 {
            regs.extend([Register::R12, Register::R13, Register::R14, Register::R15]);
        }
        if windows || self.id == ArchId::X86 {
            regs.extend([Register::RSI, Register::RDI]);
        }
        regs.into_iter().map(|r| Reg(r as u16)).collect()
    }

    fn stack_pointer(&self) -> Option<Reg> {
        Some(Reg(Register::RSP as u16))
    }

    fn mem_addr(&self, insn: &Insn) -> Option<(Addr, Access)> {
        let access = insn.mem?.access;
        let (instr, bitness) = self
            .decode_raw(insn.bytes.as_slice(), insn.va, insn.mode)
            .ok()?;
        (0..instr.op_count())
            .any(|i| instr.op_kind(i) == OpKind::Memory)
            .then(|| address(&instr, bitness))
            .flatten()
            .map(|a| (a, access))
    }

    fn reg_name(&self, r: RegPart) -> String {
        Register::values()
            .find(|&x| part(x) == Some(r))
            .map_or_else(
                || format!("r{}.{}", r.reg.0, r.bits),
                |x| format!("{x:?}").to_lowercase(),
            )
    }
}

/// A general-purpose register's low bits. The high-byte registers (`ah`...)
/// are not low bits, and are left out.
fn part(r: Register) -> Option<RegPart> {
    if !r.is_gpr() || matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) {
        return None;
    }
    Some(RegPart {
        reg: Reg(r.full_register() as u16),
        bits: (r.size() * 8) as u8,
    })
}

/// The memory operand's address. Segment-based operands (`fs:`), vector
/// indices and an address size other than the mode's are not followed.
fn address(instr: &Instruction, bitness: u32) -> Option<Addr> {
    if matches!(instr.memory_segment(), Register::FS | Register::GS) {
        return None;
    }
    if instr.is_ip_rel_memory_operand() {
        return Some(Addr {
            base: None,
            index: None,
            disp: instr.ip_rel_memory_address() as i64,
        });
    }
    let full = |r: Register| r.is_gpr() && r.size() * 8 == bitness as usize;
    let (b, i) = (instr.memory_base(), instr.memory_index());
    if (b != Register::None && !full(b)) || (i != Register::None && !full(i)) {
        return None;
    }
    let raw = instr.memory_displacement64();
    let disp = match bitness {
        16 => i64::from(raw as u16 as i16),
        32 => i64::from(raw as u32 as i32),
        _ => raw as i64,
    };
    Some(Addr {
        base: (b != Register::None).then(|| Reg(b.full_register() as u16)),
        index: (i != Register::None).then(|| Index {
            reg: RegPart {
                reg: Reg(i.full_register() as u16),
                bits: bitness as u8,
            },
            signed: false,
            shift: instr.memory_index_scale().trailing_zeros() as u8,
        }),
        disp,
    })
}

/// Operand `op` as a value read at `bits` (immediates are cut to that width).
fn value(instr: &Instruction, op: u32, bits: u32, bitness: u32) -> Option<Value> {
    Some(match instr.op_kind(op) {
        OpKind::Register => Value::Reg {
            part: part(instr.op_register(op))?,
            signed: false,
            shift: 0,
        },
        OpKind::Memory => Value::Load {
            addr: address(instr, bitness)?,
            bytes: u8::try_from(instr.memory_size().size())
                .ok()
                .filter(|b| matches!(b, 1 | 2 | 4 | 8))?,
            signed: false,
        },
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Value::Imm {
            value: match bits {
                64 => instr.immediate(op),
                b => instr.immediate(op) & ((1u64 << b) - 1),
            },
        },
        _ => return None,
    })
}

/// The effects M1 follows values through, when the operands are ones it can
/// name.
fn known_effect(instr: &Instruction, bitness: u32) -> Option<Effect> {
    let dst = || {
        (instr.op_kind(0) == OpKind::Register)
            .then(|| part(instr.op_register(0)))
            .flatten()
    };
    let signed = |v: Value| match v {
        Value::Reg { part, shift, .. } => Value::Reg {
            part,
            signed: true,
            shift,
        },
        Value::Load { addr, bytes, .. } => Value::Load {
            addr,
            bytes,
            signed: true,
        },
        v => v,
    };
    let binary = |op: BinOp, flags: Flags| -> Option<Effect> {
        let dst = dst()?;
        Some(Effect::Binary {
            op,
            dst,
            a: Value::Reg {
                part: dst,
                signed: false,
                shift: 0,
            },
            b: value(instr, 1, u32::from(dst.bits), bitness)?,
            flags,
        })
    };
    match instr.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx => {
            let dst = dst()?;
            let src = value(instr, 1, u32::from(dst.bits), bitness)?;
            Some(Effect::Move { dst, src })
        }
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            let dst = dst()?;
            let src = signed(value(instr, 1, u32::from(dst.bits), bitness)?);
            Some(Effect::Move { dst, src })
        }
        Mnemonic::Cdqe => Some(Effect::Move {
            dst: part(Register::RAX)?,
            src: Value::Reg {
                part: part(Register::EAX)?,
                signed: true,
                shift: 0,
            },
        }),
        Mnemonic::Lea => Some(Effect::Move {
            dst: dst()?,
            src: Value::Address {
                addr: address(instr, bitness)?,
            },
        }),
        Mnemonic::Add => binary(BinOp::Add, Flags::Changed),
        Mnemonic::Sub => binary(BinOp::Sub, Flags::Compare),
        Mnemonic::And => binary(BinOp::And, Flags::Changed),
        Mnemonic::Shl => binary(BinOp::Shl, Flags::Changed),
        Mnemonic::Cmp => {
            let bits = match instr.op_kind(0) {
                OpKind::Register => instr.op_register(0).size() * 8,
                _ => instr.memory_size().size() * 8,
            } as u32;
            Some(Effect::Compare {
                a: value(instr, 0, bits, bitness)?,
                b: value(instr, 1, bits, bitness)?,
            })
        }
        // `loop` and `jrcxz` test a register, not the flags, and `loop` writes it.
        _ if instr.flow_control() == FlowControl::ConditionalBranch
            && instr.condition_code() != ConditionCode::None =>
        {
            Some(Effect::Branch {
                cond: match instr.condition_code() {
                    ConditionCode::e => Cond::Eq,
                    ConditionCode::ne => Cond::Ne,
                    ConditionCode::b => Cond::Below,
                    ConditionCode::be => Cond::BelowOrEqual,
                    ConditionCode::a => Cond::Above,
                    ConditionCode::ae => Cond::AboveOrEqual,
                    _ => Cond::Other,
                },
            })
        }
        _ => None,
    }
}

/// Any other instruction: the general-purpose registers it may write, and
/// whether it may change the flags.
fn other_effect(instr: &Instruction) -> Effect {
    INFO.with(|f| {
        let mut f = f.borrow_mut();
        let info = f.info_options(instr, InstructionInfoOptions::NO_MEMORY_USAGE);
        let mut writes: Vec<Reg> = info
            .used_registers()
            .iter()
            .filter(|u| {
                u.register().is_gpr() && !matches!(u.access(), OpAccess::Read | OpAccess::CondRead)
            })
            .map(|u| Reg(u.register().full_register() as u16))
            .collect();
        writes.sort();
        writes.dedup();
        Effect::Other {
            writes,
            all: false,
            flags: instr.rflags_modified() != 0,
        }
    })
}

/// With ignored prefixes shown, iced also prints the `F2` / `F3` byte that it
/// already named `xacquire` / `xrelease` as `repne` / `rep`. One byte, one word.
fn drop_shadowed_prefixes(tokens: &mut Vec<Token>) {
    let has = |w: &str| {
        tokens
            .iter()
            .any(|t| t.kind == TokenKind::Prefix && t.text == w)
    };
    let shadowed = match (has("xacquire"), has("xrelease")) {
        (true, _) => "repne",
        (_, true) => "rep",
        _ => return,
    };
    if let Some(i) = tokens
        .iter()
        .position(|t| t.kind == TokenKind::Prefix && t.text == shadowed)
    {
        tokens.remove(i);
        if tokens.get(i).is_some_and(|t| t.kind == TokenKind::Space) {
            tokens.remove(i);
        }
    }
}

/// iced writes a direct far pointer as `far offset,selector`; Intel and GNU
/// syntax write `selector:offset`.
fn far_pointer(tokens: &mut [Token], instr: &Instruction) {
    if !matches!(instr.op_kind(0), OpKind::FarBranch16 | OpKind::FarBranch32) {
        return;
    }
    let selector = u64::from(instr.far_branch_selector());
    let offset = match instr.op_kind(0) {
        OpKind::FarBranch16 => u64::from(instr.far_branch16()),
        _ => u64::from(instr.far_branch32()),
    };
    let numbers: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.value.is_some())
        .map(|(i, _)| i)
        .collect();
    if let [a, b] = numbers[..]
        && b == a + 2
        && tokens[a + 1].text == ","
    {
        tokens[a] = Token::with_value(TokenKind::Number, format!("{selector:#x}"), selector);
        tokens[a + 1] = Token::new(TokenKind::Punct, ":");
        tokens[b] = Token::with_value(TokenKind::Address, format!("{offset:#x}"), offset);
    }
}

fn flow(instr: &Instruction) -> Flow {
    let near = matches!(
        instr.op_kind(0),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    let target = || Va(instr.near_branch_target());
    // `hlt` faults in user mode, and in a kernel only an interrupt resumes it.
    if instr.mnemonic() == Mnemonic::Hlt {
        return Flow::Trap;
    }
    match instr.flow_control() {
        FlowControl::Next => Flow::Next,
        FlowControl::UnconditionalBranch if near => Flow::Jump { target: target() },
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::ConditionalBranch if near => Flow::Branch { target: target() },
        FlowControl::ConditionalBranch => Flow::IndirectJump,
        FlowControl::Call if near => Flow::Call { target: target() },
        // System calls (`syscall`, `sysenter`, `vmcall`...) name no target:
        // the kernel or hypervisor runs and execution normally resumes.
        FlowControl::Call | FlowControl::IndirectCall if instr.op_count() == 0 => Flow::Interrupt,
        FlowControl::Call | FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::Return => Flow::Return,
        FlowControl::Interrupt => Flow::Interrupt,
        // xbegin names its abort handler like a conditional branch; xend and
        // xabort continue (an abort resumes at the handler xbegin recorded).
        FlowControl::XbeginXabortXend if near => Flow::Branch { target: target() },
        FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::Exception => Flow::Trap,
    }
}

fn mem_ref(instr: &Instruction) -> Option<MemRef> {
    let op = (0..instr.op_count()).find(|&i| instr.op_kind(i) == OpKind::Memory)?;
    let (access, conditional) = INFO.with(|f| {
        let mut f = f.borrow_mut();
        let info = f.info_options(
            instr,
            InstructionInfoOptions::NO_REGISTER_USAGE | InstructionInfoOptions::NO_MEMORY_USAGE,
        );
        match info.op_access(op) {
            OpAccess::Read => (Access::Read, false),
            OpAccess::CondRead => (Access::Read, true),
            OpAccess::Write => (Access::Write, false),
            OpAccess::CondWrite => (Access::Write, true),
            OpAccess::ReadWrite => (Access::ReadWrite, false),
            OpAccess::ReadCondWrite => (Access::ReadWrite, true),
            _ => (Access::Address, false),
        }
    });
    let segment_based = matches!(instr.memory_segment(), Register::FS | Register::GS);
    let size = instr.memory_size().size() as u32;
    let raw = instr.memory_displacement64();
    let (addr, pc_relative, displacement) = if instr.is_ip_rel_memory_operand() {
        let target = instr.ip_rel_memory_address();
        let disp = i64::from(target.wrapping_sub(instr.next_ip()) as i32);
        (Some(Va(target)), true, disp)
    } else {
        // iced stores the displacement extended to the address size (and already
        // scaled for AVX-512's compressed disp8), so reading it back at that width
        // gives the signed value.
        let width = [instr.memory_base(), instr.memory_index()]
            .into_iter()
            .find(|r| r.is_gpr())
            .map_or(8, |r| r.size());
        let disp = match width {
            2 => i64::from(raw as u16 as i16),
            4 => i64::from(raw as u32 as i32),
            _ => raw as i64,
        };
        let absolute = instr.memory_base() == Register::None
            && instr.memory_index() == Register::None
            && !segment_based;
        (absolute.then_some(Va(raw)), false, disp)
    };
    Some(MemRef::new(
        addr,
        pc_relative,
        segment_based,
        displacement,
        size,
        access,
        conditional,
    ))
}

/// The first immediate, at its operand size: sign-extended forms (`push -0x10`
/// is `0xfffffff0` in 32-bit code) stop at that size instead of 64 bits.
fn immediate(instr: &Instruction) -> Option<u64> {
    (0..instr.op_count()).find_map(|i| {
        let bits = match instr.op_kind(i) {
            OpKind::Immediate8 | OpKind::Immediate8_2nd => 8,
            OpKind::Immediate16 | OpKind::Immediate8to16 => 16,
            OpKind::Immediate32 | OpKind::Immediate8to32 => 32,
            OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 64,
            _ => return None,
        };
        let v = instr.immediate(i);
        Some(if bits == 64 { v } else { v & ((1 << bits) - 1) })
    })
}

thread_local! {
    static INTEL: RefCell<IntelFormatter> = RefCell::new(intel_formatter());
    static GAS: RefCell<GasFormatter> = RefCell::new(gas_formatter());
    static INFO: RefCell<InstructionInfoFactory> = RefCell::new(InstructionInfoFactory::new());
}

/// Number style shared by both syntaxes: `0x`-prefixed lowercase hex without
/// leading zeros, as GNU tools print it.
fn common_options(f: &mut dyn Formatter) {
    let o = f.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_leading_zeros(false);
    o.set_branch_leading_zeros(false);
    o.set_displacement_leading_zeros(false);
    o.set_small_hex_numbers_in_decimal(false);
    o.set_add_leading_zero_to_hex_numbers(false);
    o.set_show_branch_size(false);
    // `true` keeps `[rip+0x2edb]` as encoded; the listing adds the target.
    o.set_rip_relative_addresses(true);
    o.set_space_after_operand_separator(false);
    // Show the encoding as written: `[rax+rax*1+0x0]` for a SIB byte with a zero
    // disp8, and prefixes the CPU ignores (`cs` on padding `nop`s).
    o.set_show_zero_displacements(true);
    o.set_always_show_scale(true);
    o.set_show_useless_prefixes(true);
}

fn intel_formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    common_options(&mut f);
    f.options_mut()
        .set_memory_size_options(MemorySizeOptions::Always);
    f
}

fn gas_formatter() -> GasFormatter {
    let mut f = GasFormatter::new();
    common_options(&mut f);
    // AT&T has no `*1` without an index register: iced would print `(%rbx,)`.
    f.options_mut().set_always_show_scale(false);
    f
}

/// Collects formatter output as typed tokens.
#[derive(Default)]
struct Tokens(Vec<Token>);

impl Tokens {
    fn push(&mut self, kind: TokenKind, text: &str, value: Option<u64>) {
        // Merge runs of plain text of one kind (spaces, punctuation, keywords);
        // registers, numbers and addresses stay separate tokens.
        let mergeable = matches!(
            kind,
            TokenKind::Space | TokenKind::Punct | TokenKind::Keyword
        );
        if let (Some(last), None, true) = (self.0.last_mut(), value, mergeable)
            && last.kind == kind
        {
            last.text.push_str(text);
            return;
        }
        self.0.push(match value {
            Some(v) => Token::with_value(kind, text, v),
            None => Token::new(kind, text),
        });
    }
}

fn token_kind(text: &str, kind: FormatterTextKind) -> TokenKind {
    match kind {
        _ if text.trim().is_empty() => TokenKind::Space,
        FormatterTextKind::Prefix => TokenKind::Prefix,
        FormatterTextKind::Mnemonic => TokenKind::Mnemonic,
        FormatterTextKind::Keyword | FormatterTextKind::Directive => TokenKind::Keyword,
        FormatterTextKind::Register => TokenKind::Register,
        FormatterTextKind::Decorator => TokenKind::Decorator,
        FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => TokenKind::Address,
        FormatterTextKind::Label | FormatterTextKind::Function => TokenKind::Symbol,
        FormatterTextKind::Number | FormatterTextKind::SelectorValue | FormatterTextKind::Data => {
            TokenKind::Number
        }
        _ => TokenKind::Punct,
    }
}

impl FormatterOutput for Tokens {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        self.push(token_kind(text, kind), text, None);
    }

    fn write_number(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        text: &str,
        value: u64,
        _number_kind: NumberKind,
        kind: FormatterTextKind,
    ) {
        self.push(token_kind(text, kind), text, Some(value));
    }
}
