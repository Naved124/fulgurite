//! What an instruction does to registers and flags ([`Effect`]), read from
//! the encoding's fields.
//!
//! Registers are numbered as in the encoding: `x0`–`x30` are 0–30 and the
//! stack pointer is 31. Register 31 read as the zero register is the constant
//! 0, and a write to it is dropped. The forms jump tables and address pairs
//! use are described exactly (`adrp`, `adr`, `add`/`sub` in their immediate,
//! shifted and extended forms, `movz`, `mov`, loads with an immediate,
//! register or literal address, `b.cond`, `br`). Every other instruction of
//! the base integer, load/store, branch, system and SIMD&FP classes is
//! [`Effect::Other`] with the general-purpose registers it may write;
//! anything else (SVE, SME, atomics) may write any register.

use fg_ir::{Access, Addr, BinOp, Cond, Effect, Flags, Index, Insn, Reg, RegPart, Value};

/// The stack pointer's number.
pub(crate) const SP: u16 = 31;

fn x(n: u32) -> Reg {
    Reg(n as u16)
}

/// Register `n` read at `bits`, where 31 is the zero register.
fn read_zr(n: u32, bits: u8, signed: bool, shift: u8) -> Value {
    if n == 31 {
        Value::Imm { value: 0 }
    } else {
        Value::Reg {
            part: RegPart { reg: x(n), bits },
            signed,
            shift,
        }
    }
}

/// Register `n` read at `bits`, where 31 is the stack pointer.
fn read_sp(n: u32, bits: u8) -> Value {
    Value::Reg {
        part: RegPart { reg: x(n), bits },
        signed: false,
        shift: 0,
    }
}

/// The destination `n` at `bits`; `None` for the zero register.
fn dst_zr(n: u32, bits: u8) -> Option<RegPart> {
    (n != 31).then_some(RegPart { reg: x(n), bits })
}

/// The lower-case class part of an encoding name (`addsub_imm` for
/// `ADD_64_addsub_imm`, `ldst_regoff` for `LDRB_32BL_ldst_regoff`).
fn class(name: &str) -> String {
    name.split('_')
        // `only` stands for an encoding with no variants (`B_only_condbranch`).
        .filter(|p| p.chars().any(|c| c.is_ascii_lowercase()) && *p != "only")
        .collect::<Vec<_>>()
        .join("_")
}

const NOTHING: Effect = Effect::Other {
    writes: Vec::new(),
    all: false,
    flags: false,
};

/// The effect of `w`, an instruction of encoding `name` at `insn`.
pub(crate) fn effect(name: &str, w: u32, insn: &Insn) -> Effect {
    exact(name, w, insn).unwrap_or_else(|| other(name, w))
}

fn exact(name: &str, w: u32, insn: &Insn) -> Option<Effect> {
    let (rd, rn, rm) = (w & 31, (w >> 5) & 31, (w >> 16) & 31);
    let bits: u8 = if w >> 31 == 1 { 64 } else { 32 };
    let base = name.split('_').next().unwrap_or("");
    let class = class(name);
    let target = || insn.mem.as_ref().and_then(|m| m.addr).map(|a| a.0 as i64);
    match class.as_str() {
        "pcreladdr" => Some(Effect::Move {
            dst: dst_zr(rd, 64)?,
            src: Value::Address {
                addr: Addr {
                    base: None,
                    index: None,
                    disp: target()?,
                },
            },
        }),
        "addsub_imm" | "addsub_shift" | "addsub_ext" => {
            let flags_set = base.ends_with('S');
            let sub = base.starts_with("SUB");
            let (a, b) = match class.as_str() {
                "addsub_imm" => {
                    let imm = u64::from((w >> 10) & 0xfff) << (12 * ((w >> 22) & 1));
                    (read_sp(rn, bits), Value::Imm { value: imm })
                }
                "addsub_shift" => {
                    // Only LSL is followed.
                    if (w >> 22) & 3 != 0 {
                        return None;
                    }
                    let amount = ((w >> 10) & 63) as u8;
                    (
                        read_zr(rn, bits, false, 0),
                        read_zr(rm, bits, false, amount),
                    )
                }
                _ => {
                    let option = (w >> 13) & 7;
                    let amount = ((w >> 10) & 7) as u8;
                    if amount > 4 {
                        return None;
                    }
                    let from = [8, 16, 32, 64][(option & 3) as usize];
                    (
                        read_sp(rn, bits),
                        read_zr(rm, from.min(bits), option & 4 != 0, amount),
                    )
                }
            };
            // The destination is the stack pointer in the immediate and
            // extended forms that do not set flags, the zero register otherwise.
            let dst = if rd == 31 && !flags_set && class != "addsub_shift" {
                Some(RegPart { reg: Reg(SP), bits })
            } else {
                dst_zr(rd, bits)
            };
            let flags = match (flags_set, sub) {
                (false, _) => Flags::Kept,
                (true, true) => Flags::Compare,
                (true, false) => Flags::Changed,
            };
            Some(match dst {
                Some(dst) => Effect::Binary {
                    op: if sub { BinOp::Sub } else { BinOp::Add },
                    dst,
                    a,
                    b,
                    flags,
                },
                None if flags == Flags::Compare => Effect::Compare { a, b },
                None => Effect::Other {
                    writes: Vec::new(),
                    all: false,
                    flags: flags_set,
                },
            })
        }
        "movewide" if base == "MOVZ" || base == "MOVN" => {
            let hw = (w >> 21) & 3;
            if bits == 32 && hw > 1 {
                return None;
            }
            let v = u64::from((w >> 5) & 0xffff) << (16 * hw);
            let v = if base == "MOVN" { !v } else { v };
            let v = if bits == 32 { v & 0xffff_ffff } else { v };
            Some(match dst_zr(rd, bits) {
                Some(dst) => Effect::Move {
                    dst,
                    src: Value::Imm { value: v },
                },
                None => NOTHING,
            })
        }
        // `mov xd, xm` is `orr xd, xzr, xm`.
        "log_shift" if base == "ORR" && rn == 31 && (w >> 10) & 63 == 0 && (w >> 21) & 7 == 0 => {
            Some(match dst_zr(rd, bits) {
                Some(dst) => Effect::Move {
                    dst,
                    src: read_zr(rm, bits, false, 0),
                },
                None => NOTHING,
            })
        }
        "ldst_pos" | "ldst_regoff" | "ldst_unscaled" | "loadlit"
            if base.starts_with("LDR") || base.starts_with("LDUR") =>
        {
            let (bytes, signed) = match base {
                "LDRB" | "LDURB" => (1, false),
                "LDRH" | "LDURH" => (2, false),
                "LDRSB" | "LDURSB" => (1, true),
                "LDRSH" | "LDURSH" => (2, true),
                "LDRSW" | "LDURSW" => (4, true),
                "LDR" | "LDUR" => (0, false),
                _ => return None,
            };
            // The register class follows the mnemonic: `32`, `64`, or a
            // SIMD&FP register (`B`, `H`, `S`, `D`, `Q`), which no general
            // register receives.
            let width = name.split('_').nth(1).unwrap_or("");
            let dst_bits = if width.starts_with("64") {
                64
            } else if width.starts_with("32") {
                32
            } else {
                return Some(NOTHING);
            };
            let bytes: u8 = if bytes == 0 { dst_bits / 8 } else { bytes };
            let addr = match class.as_str() {
                "loadlit" => Addr {
                    base: None,
                    index: None,
                    disp: target()?,
                },
                "ldst_pos" => Addr {
                    base: Some(x(rn)),
                    index: None,
                    disp: i64::from((w >> 10) & 0xfff) * i64::from(bytes),
                },
                "ldst_unscaled" => Addr {
                    base: Some(x(rn)),
                    index: None,
                    disp: crate::helpers::sext(i64::from((w >> 12) & 0x1ff), 9),
                },
                _ => {
                    let option = (w >> 13) & 7;
                    if option & 2 == 0 || rm == 31 {
                        return None;
                    }
                    let shift = if (w >> 12) & 1 == 1 {
                        bytes.trailing_zeros() as u8
                    } else {
                        0
                    };
                    Addr {
                        base: Some(x(rn)),
                        index: Some(Index {
                            reg: RegPart {
                                reg: x(rm),
                                bits: if option & 1 == 1 { 64 } else { 32 },
                            },
                            signed: option & 4 != 0,
                            shift,
                        }),
                        disp: 0,
                    }
                }
            };
            Some(match dst_zr(rd, dst_bits) {
                Some(dst) => Effect::Move {
                    dst,
                    src: Value::Load {
                        addr,
                        bytes,
                        signed,
                    },
                },
                None => NOTHING,
            })
        }
        "condbranch" => Some(Effect::Branch {
            cond: match w & 15 {
                0 => Cond::Eq,
                1 => Cond::Ne,
                2 => Cond::AboveOrEqual,
                3 => Cond::Below,
                8 => Cond::Above,
                9 => Cond::BelowOrEqual,
                _ => Cond::Other,
            },
        }),
        "branch_reg" if base == "BR" => Some(Effect::Jump {
            target: read_zr(rn, 64, false, 0),
        }),
        "branch_reg" if base == "BLR" => Some(Effect::Call {
            target: read_zr(rn, 64, false, 0),
        }),
        _ => None,
    }
}

/// The address of the memory operand of `w`, an instruction of encoding
/// `name` at `insn`, whatever the access. Post-indexed forms use the base as
/// it is before the update. SIMD structure loads and stores, tag and
/// pointer-authenticated accesses are not described.
pub(crate) fn mem_addr(name: &str, w: u32, insn: &Insn) -> Option<(Addr, Access)> {
    let op = name.split('_').next().unwrap_or("");
    let access = if op.starts_with("PRFM") || op.starts_with("PRFUM") {
        Access::Address
    } else if class(name).starts_with("memop") || class(name).starts_with("comswap") {
        // Atomics (`ldadd`, `swp`, `cas`) read and write; `stadd` and the
        // like are `ldadd` without a destination.
        Access::ReadWrite
    } else if op.starts_with("ST") {
        Access::Write
    } else {
        Access::Read
    };
    mem_operand(name, w, insn).map(|a| (a, access))
}

fn mem_operand(name: &str, w: u32, insn: &Insn) -> Option<Addr> {
    let class = class(name);
    let c = class.as_str();
    let base = |disp: i64| {
        Some(Addr {
            base: Some(x((w >> 5) & 31)),
            index: None,
            disp,
        })
    };
    let vector = (w >> 26) & 1 == 1;
    let size = w >> 30;
    // Bytes accessed, as a power of two, for the scaled offsets.
    let scale = || {
        let opc = (w >> 22) & 3;
        if vector && size == 0 && opc & 2 != 0 {
            4
        } else {
            size
        }
    };
    let simm9 = || crate::helpers::sext(i64::from((w >> 12) & 0x1ff), 9);
    match c {
        "loadlit" => Some(Addr {
            base: None,
            index: None,
            disp: insn.mem.as_ref()?.addr?.0 as i64,
        }),
        "ldst_pos" => base(i64::from((w >> 10) & 0xfff) << scale()),
        "ldst_unscaled" | "ldst_unpriv" | "ldapstl_unscaled" | "ldst_immpre" => base(simm9()),
        "ldst_immpost" | "ldstpair_post" => base(0),
        "ldst_regoff" => {
            let (rm, option) = ((w >> 16) & 31, (w >> 13) & 7);
            if option & 2 == 0 {
                return None;
            }
            let shift = if (w >> 12) & 1 == 1 { scale() as u8 } else { 0 };
            Some(Addr {
                base: Some(x((w >> 5) & 31)),
                // Register 31 is the zero register here.
                index: (rm != 31).then(|| Index {
                    reg: RegPart {
                        reg: x(rm),
                        bits: if option & 1 == 1 { 64 } else { 32 },
                    },
                    signed: option & 4 != 0,
                    shift,
                }),
                disp: 0,
            })
        }
        "ldstpair_off" | "ldstpair_pre" | "ldstnapair_offs" => {
            let scale = if vector { 2 + size } else { 2 + (size >> 1) };
            base(crate::helpers::sext(i64::from((w >> 15) & 0x7f), 7) << scale)
        }
        _ if c.starts_with("memop")
            || c.starts_with("ldstexcl")
            || c.starts_with("comswap")
            || c == "ldstord" =>
        {
            base(0)
        }
        _ => None,
    }
}

/// The general-purpose registers any other instruction may write.
fn other(name: &str, w: u32) -> Effect {
    let (rd, rn) = (w & 31, (w >> 5) & 31);
    let base = name.split('_').next().unwrap_or("");
    let class = class(name);
    let c = class.as_str();
    let mut writes = Vec::new();
    let mut flags = false;
    let mut write = |n: u32| {
        if n != 31 {
            writes.push(x(n));
        }
    };
    let is = |p: &str| c.starts_with(p);
    if is("addsub") || is("log_") || is("bitfield") || is("extract") || is("movewide") {
        // `and sp, x0, #mask` and `add sp, x0, x1, uxtx` write the stack
        // pointer; the shifted forms and the flag-setting ones write the zero
        // register.
        let sets = base.ends_with('S');
        if rd == 31 && !sets && (c == "addsub_imm" || c == "addsub_ext" || c == "log_imm") {
            writes.push(Reg(SP));
        } else {
            write(rd);
        }
        flags = sets && (is("addsub") || is("log_"));
    } else if is("dp_") || c == "condsel" || c == "addsub_carry" {
        write(rd);
        flags = matches!(base, "ADCS" | "SBCS");
    } else if c.starts_with("condcmp") || c == "rmif" || c == "setf" {
        flags = true;
    } else if matches!(
        c,
        "condbranch"
            | "compbranch"
            | "testbranch"
            | "branch_imm"
            | "branch_reg"
            | "hints"
            | "barriers"
    ) {
        // Calls are not asked for (they change every register a call may).
    } else if c == "pstate" || c.starts_with("system") {
        if matches!(base, "MRS" | "SYSL") {
            write(rd);
        }
        flags = true;
    } else if matches!(
        c,
        "ldst_pos"
            | "ldst_regoff"
            | "ldst_unscaled"
            | "ldst_immpre"
            | "ldst_immpost"
            | "ldst_unpriv"
            | "ldstpair_off"
            | "ldstpair_pre"
            | "ldstpair_post"
            | "loadlit"
    ) {
        let width = name.split('_').nth(1).unwrap_or("");
        let general = width.starts_with("32") || width.starts_with("64");
        if base.starts_with("LD") && general {
            write(rd);
            if c.starts_with("ldstpair") {
                write((w >> 10) & 31);
            }
        }
        if c.ends_with("pre") || c.ends_with("post") {
            writes.push(x(rn));
        }
    } else if c.starts_with("float2") || c.starts_with("asimdins") {
        // Moves and conversions between general and SIMD&FP registers, in
        // either direction: the general register may be written.
        write(rd);
    } else if c.starts_with("floatcmp") || c.starts_with("floatccmp") {
        flags = true;
    } else if c.starts_with("float")
        || c.starts_with("asimd")
        || c.starts_with("asisd")
        || c.starts_with("crypto")
    {
        // SIMD&FP registers only.
    } else {
        return Effect::UNKNOWN;
    }
    writes.sort();
    writes.dedup();
    Effect::Other {
        writes,
        all: false,
        flags,
    }
}
