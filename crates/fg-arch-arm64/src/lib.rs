//! AArch64 (ARM64) for Fulgurite.
//!
//! The decoder is generated from Arm's machine-readable specification (design
//! §7.3): `tables.rs` holds the decode tree, every encoding's assembler template,
//! the alias rules and the operand definitions, written by `tools/arm64/gen.py`
//! from the A-profile Machine Readable Specification (JSON) and the A64 ISA XML.
//! This crate interprets those tables: it walks the decode tree to find the
//! encoding, picks the preferred alias, and renders the template into typed
//! tokens. Reserved encodings (no decode-tree match, an operand value the
//! specification marks reserved) are reported as invalid.
//!
//! Text follows Arm's assembler syntax in lower case, with immediates in decimal
//! and logical immediates in hexadecimal as `llvm-mc` prints them; branch and
//! literal targets are absolute addresses. The lifter (M2) will live here too.

#![forbid(unsafe_code)]

mod effect;
mod helpers;
mod model;
mod render;
#[rustfmt::skip]
mod tables;

use fg_core::{ArchId, Va};
use fg_ir::{
    Access, Arch, DecodeError, Effect, Flow, Insn, MemRef, Mode, Reg, RegPart, Syntax, Token,
    TokenKind,
};
use model::Node;
use render::{Fail, render};
use tables::{ALIASES, ENCODINGS, NODES, NOT_DECODED, SYSREG_READ, SYSREG_WRITE, cond, undefined};

/// Every A64 instruction is four bytes.
pub const INSN_LEN: usize = 4;

/// The AArch64 architecture module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64;

/// The AArch64 module.
pub static ARM64: Arm64 = Arm64;

/// A decoded word: its encoding, the template used and the tokens.
struct Decoded {
    enc: usize,
    tokens: Vec<Token>,
}

/// Finds the encoding of `w` in the decode tree.
fn find(w: u32) -> Option<usize> {
    let mut node: &Node = &NODES[0];
    if w & node.mask != node.value {
        return None;
    }
    'down: loop {
        let first = usize::from(node.first);
        for child in &NODES[first..first + usize::from(node.count)] {
            if w & child.mask == child.value && cond(child.cond, w) {
                if child.enc != 0xFFFF {
                    return Some(usize::from(child.enc));
                }
                node = child;
                continue 'down;
            }
        }
        return None;
    }
}

/// Decodes and renders one word, using the preferred alias when there is one.
fn decode_word(w: u32, pc: u64) -> Option<Decoded> {
    let enc = find(w)?;
    let e = &ENCODINGS[enc];
    if undefined(e.undef, w) {
        return None;
    }
    // The encoding's own template checks every field (reserved values and
    // ranges); an alias may describe the same bits differently.
    let base = render(w, pc, e.items, e.len).ok()?;
    let start = usize::from(e.alias);
    for a in &ALIASES[start..start + usize::from(e.aliases)] {
        if cond(a.cond, w) && cond(a.preferred, w) {
            match render(w, pc, a.items, a.len) {
                Ok(tokens) => return Some(Decoded { enc, tokens }),
                Err(Fail::Reserved) => return None,
                Err(Fail::NoEntry) => {}
            }
        }
    }
    Some(Decoded { enc, tokens: base })
}

/// True if `word` decodes but its fields reach a CONSTRAINED UNPREDICTABLE
/// case of the decode pseudocode (overlapping registers in a load pair, a
/// writeback base that is also loaded...). Such words are decoded as the
/// instruction they encode; real CPUs may treat them differently.
pub fn is_unpredictable(word: u32) -> bool {
    find(word).is_some_and(|e| undefined(ENCODINGS[e].unpred, word))
}

/// One encoding of the generated tables, for tests and tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodingInfo {
    /// Arm's name (`ADD_64_addsub_imm`).
    pub name: &'static str,
    /// Bits the encoding fixes.
    pub mask: u32,
    /// Their values.
    pub value: u32,
    /// Bits that should have a value; others make the word CONSTRAINED
    /// UNPREDICTABLE but it still decodes.
    pub should_be_mask: u32,
    /// The values they should have.
    pub should_be_value: u32,
}

/// Every encoding the decoder knows.
pub fn encodings() -> impl Iterator<Item = EncodingInfo> {
    ENCODINGS
        .iter()
        .filter(|e| !e.name.is_empty())
        .map(|e| EncodingInfo {
            name: e.name,
            mask: e.mask,
            value: e.value,
            should_be_mask: e.sb_mask,
            should_be_value: e.sb_value,
        })
}

/// `adrp xd, label`: the register written and the 4 KiB page it receives.
///
/// With [`load_offset`] this resolves the address pairs compilers and linkers
/// emit (`adrp x16, page` + `ldr x17, [x16, #off]` in a PLT stub). Recovering
/// them across a function is the job of analysis (M1); these helpers serve
/// local patterns.
pub fn adrp(word: u32, pc: u64) -> Option<(u8, u64)> {
    if word & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo = i64::from((word >> 29) & 3);
    let immhi = i64::from((word >> 5) & 0x7_ffff);
    let imm = helpers::sext((immhi << 2) | immlo, 21) << 12;
    Some(((word & 0x1f) as u8, (pc & !0xfff).wrapping_add(imm as u64)))
}

/// `ldr xt, [xn, #imm]` / `ldr wt, [xn, #imm]` (unsigned offset): the base
/// register and the byte offset.
pub fn load_offset(word: u32) -> Option<(u8, u64)> {
    let scale = match find(word).map(|e| ENCODINGS[e].name)? {
        "LDR_64_ldst_pos" => 8,
        "LDR_32_ldst_pos" => 4,
        _ => return None,
    };
    Some((
        ((word >> 5) & 0x1f) as u8,
        u64::from((word >> 10) & 0xfff) * scale,
    ))
}

/// Encodings in Arm's machine-readable specification that this decoder
/// leaves out because the XML release does not describe their operands yet
/// (name, fixed-bit mask, value). Words matching them are reported invalid.
pub fn encodings_not_decoded() -> impl Iterator<Item = (&'static str, u32, u32)> {
    NOT_DECODED.iter().copied()
}

/// Arm's name for system register encoding `op0:op1:CRn:CRm:op2` (16 bits,
/// as in MRS/MSR), lower case: the name for reads, or for writes with
/// `write`. `None` where `Registers.json` defines no register in that
/// direction.
pub fn system_register(enc: u16, write: bool) -> Option<&'static str> {
    let table: &[(u16, &str)] = if write { &SYSREG_WRITE } else { &SYSREG_READ };
    table
        .binary_search_by_key(&enc, |e| e.0)
        .ok()
        .map(|i| table[i].1)
}

/// Every system register name of the specification, reads then writes (a
/// register both read and written appears twice).
pub fn system_register_names() -> impl Iterator<Item = &'static str> {
    SYSREG_READ.iter().chain(SYSREG_WRITE.iter()).map(|e| e.1)
}

/// Arm's name for the encoding of `word` (`ADD_64_addsub_imm`), if it is one.
pub fn encoding_name(word: u32) -> Option<&'static str> {
    find(word).map(|e| ENCODINGS[e].name)
}

/// Control flow from the encoding and its first address operand.
fn flow(name: &str, target: Option<Va>) -> Flow {
    let base = name.split('_').next().unwrap_or("");
    let branch = |kind: fn(Va) -> Flow| target.map_or(Flow::Next, kind);
    match base {
        "B" if name.contains("condbranch") => branch(|t| Flow::Branch { target: t }),
        "BC" => branch(|t| Flow::Branch { target: t }),
        "B" => branch(|t| Flow::Jump { target: t }),
        "BL" => branch(|t| Flow::Call { target: t }),
        "CBZ" | "CBNZ" | "TBZ" | "TBNZ" => branch(|t| Flow::Branch { target: t }),
        b if b.starts_with("CB") && target.is_some() => branch(|t| Flow::Branch { target: t }),
        "BR" | "BRAA" | "BRAAZ" | "BRAB" | "BRABZ" => Flow::IndirectJump,
        "BLR" | "BLRAA" | "BLRAAZ" | "BLRAB" | "BLRABZ" => Flow::IndirectCall,
        b if b.starts_with("RET") || b.starts_with("ERET") => Flow::Return,
        "SVC" | "HVC" | "SMC" => Flow::Interrupt,
        "BRK" | "HLT" | "UDF" | "DCPS1" | "DCPS2" | "DCPS3" => Flow::Trap,
        _ => Flow::Next,
    }
}

/// The PC-relative address an instruction reads or computes: literal loads,
/// `adr`, `adrp`.
fn mem_ref(name: &str, target: Option<Va>, pc: u64) -> Option<MemRef> {
    let t = target?;
    let disp = t.0.wrapping_sub(pc) as i64;
    if name.starts_with("ADR") {
        return Some(MemRef::new(
            Some(t),
            true,
            false,
            disp,
            0,
            Access::Address,
            false,
        ));
    }
    if !name.contains("loadlit") {
        return None;
    }
    let size = match name {
        n if n.starts_with("PRFM") => 0,
        n if n.contains("_32_") || n.starts_with("LDRSW") || n.contains("_S_") => 4,
        n if n.contains("_Q_") => 16,
        _ => 8,
    };
    let access = if name.starts_with("PRFM") {
        Access::Address
    } else {
        Access::Read
    };
    Some(MemRef::new(Some(t), true, false, disp, size, access, false))
}

impl Arm64 {
    fn word(bytes: &[u8]) -> Result<u32, DecodeError> {
        let b: [u8; 4] = bytes
            .get(..INSN_LEN)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_le_bytes(b))
    }
}

impl Arch for Arm64 {
    fn id(&self) -> ArchId {
        ArchId::Aarch64
    }

    fn max_insn_len(&self) -> usize {
        INSN_LEN
    }

    fn insn_alignment(&self) -> u64 {
        INSN_LEN as u64
    }

    fn decode(&self, bytes: &[u8], va: Va, mode: Mode) -> Result<Insn, DecodeError> {
        if mode != Mode::Native {
            return Err(DecodeError::UnsupportedMode);
        }
        let w = Self::word(bytes)?;
        let d = decode_word(w, va.0).ok_or(DecodeError::Invalid { len: 4 })?;
        let name = ENCODINGS[d.enc].name;
        let target = d
            .tokens
            .iter()
            .find(|t| t.kind == TokenKind::Address)
            .and_then(|t| t.value)
            .map(Va);
        let imm = d
            .tokens
            .iter()
            .find(|t| t.kind == TokenKind::Number)
            .and_then(|t| t.value);
        Ok(Insn::new(
            va,
            &bytes[..INSN_LEN],
            Mode::Native,
            flow(name, target),
            mem_ref(name, target, va.0),
            imm,
            name.starts_with("NOP_"),
        ))
    }

    fn effect(&self, insn: &Insn) -> Effect {
        let Ok(w) = Self::word(insn.bytes.as_slice()) else {
            return Effect::UNKNOWN;
        };
        match find(w) {
            Some(e) if !undefined(ENCODINGS[e].undef, w) => {
                effect::effect(ENCODINGS[e].name, w, insn)
            }
            _ => Effect::UNKNOWN,
        }
    }

    /// AAPCS64: `x19`–`x28`, the frame pointer `x29` and the stack pointer
    /// (the same on Windows).
    fn callee_saved(&self, _windows: bool) -> Vec<Reg> {
        (19..=29).chain([effect::SP]).map(Reg).collect()
    }

    fn stack_pointer(&self) -> Option<Reg> {
        Some(Reg(effect::SP))
    }

    fn mem_addr(&self, insn: &Insn) -> Option<(fg_ir::Addr, Access)> {
        let w = Self::word(insn.bytes.as_slice()).ok()?;
        let e = find(w).filter(|&e| !undefined(ENCODINGS[e].undef, w))?;
        effect::mem_addr(ENCODINGS[e].name, w, insn)
    }

    fn address_pairs(&self) -> bool {
        true
    }

    fn reg_name(&self, r: RegPart) -> String {
        match (r.reg.0, r.bits) {
            (effect::SP, 64) => "sp".to_string(),
            (effect::SP, _) => "wsp".to_string(),
            (n, 64) => format!("x{n}"),
            (n, _) => format!("w{n}"),
        }
    }

    /// Arm assembler syntax; `syntax` does not apply to AArch64.
    fn format(&self, insn: &Insn, _syntax: Syntax) -> Vec<Token> {
        let Ok(w) = Self::word(insn.bytes.as_slice()) else {
            return vec![Token::new(TokenKind::Mnemonic, "(bad)")];
        };
        match decode_word(w, insn.va.0) {
            Some(d) => d.tokens,
            None => vec![Token::new(TokenKind::Mnemonic, "(bad)")],
        }
    }
}
