//! What an instruction does to registers and flags, in the few forms that M1's
//! analyses follow a value through: jump tables (`lea`, `movsxd`, `add`,
//! `jmp`; `adrp`, `ldrb`, `adr`, `add`, `br`), the bound check before them
//! (`cmp`, `ja`) and AArch64 address pairs. Everything else is
//! [`Effect::Other`], with the registers it writes, so a value is never
//! carried across an instruction that changes it. M2's lifter supersedes this.

use serde::Serialize;

/// A register, by the architecture's number for the full-width register (x86:
/// `rax` for `eax`, `ax` and `al`; AArch64: `x0` for `w0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Reg(pub u16);

/// The low `bits` of a register: `eax` is (`rax`, 32). A write of 32 bits or
/// more clears the bits above it (x86-64, AArch64); a narrower write keeps
/// them (x86 `al`, `ax`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RegPart {
    /// The full register.
    pub reg: Reg,
    /// Width accessed: 8, 16, 32 or 64.
    pub bits: u8,
}

/// An index register in an address, extended to the address width and shifted
/// left: `rax*4` is (`rax`, 64 bits, zero, 2); AArch64 `w1, sxtw #2` is
/// (`x1`, 32 bits, sign, 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Index {
    /// The register read.
    pub reg: RegPart,
    /// True if it is sign-extended.
    pub signed: bool,
    /// Left shift (scale 4 is 2).
    pub shift: u8,
}

/// An address computed from registers: `base + index + disp`. A PC-relative
/// address has no base, and `disp` is the address itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Addr {
    /// Base register.
    pub base: Option<Reg>,
    /// Index register.
    pub index: Option<Index>,
    /// Displacement, or the whole address when there are no registers.
    pub disp: i64,
}

/// A value an instruction reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    /// A constant (AArch64's zero register reads as 0).
    Imm {
        /// The value.
        value: u64,
    },
    /// A register's low bits, extended and shifted left: `ecx` in
    /// `movsxd rax, ecx` is signed; AArch64 `w1, sxtb #2` is 8 bits, signed,
    /// shifted 2.
    Reg {
        /// The register read.
        part: RegPart,
        /// True if sign-extended, false if zero-extended.
        signed: bool,
        /// Left shift.
        shift: u8,
    },
    /// The address itself (`lea`, `adr`, `adrp`).
    Address {
        /// The address.
        addr: Addr,
    },
    /// Memory at an address, extended.
    Load {
        /// The address.
        addr: Addr,
        /// Bytes read: 1, 2, 4 or 8.
        bytes: u8,
        /// True if sign-extended (`movsx`, `movsxd`, `ldrsb`).
        signed: bool,
    },
}

/// An arithmetic operation of [`Effect::Binary`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BinOp {
    /// `a + b`.
    Add,
    /// `a - b`.
    Sub,
    /// `a & b`.
    And,
    /// `a << b`.
    Shl,
}

/// What an [`Effect::Binary`] does to the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Flags {
    /// Untouched (AArch64 `add`).
    Kept,
    /// Set as by a compare of `a` and `b` (x86 `sub`, AArch64 `subs`).
    Compare,
    /// Changed some other way (x86 `add`, `and`, `shl`).
    Changed,
}

/// The condition of a conditional branch, on the flags of the last compare
/// `a - b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Cond {
    /// `a == b`.
    Eq,
    /// `a != b`.
    Ne,
    /// `a < b`, unsigned (x86 `jb`, AArch64 `b.lo`).
    Below,
    /// `a <= b`, unsigned (`jbe`, `b.ls`).
    BelowOrEqual,
    /// `a > b`, unsigned (`ja`, `b.hi`).
    Above,
    /// `a >= b`, unsigned (`jae`, `b.hs`).
    AboveOrEqual,
    /// Any other condition (signed, sign, parity, a register test).
    Other,
}

impl Cond {
    /// The condition that holds when this one does not.
    pub fn negate(self) -> Cond {
        match self {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Below => Cond::AboveOrEqual,
            Cond::AboveOrEqual => Cond::Below,
            Cond::Above => Cond::BelowOrEqual,
            Cond::BelowOrEqual => Cond::Above,
            Cond::Other => Cond::Other,
        }
    }
}

/// What one instruction does, as far as M1's analyses follow values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Effect {
    /// `dst = src`, extended or truncated to `dst.bits`.
    Move {
        /// Written.
        dst: RegPart,
        /// Read.
        src: Value,
    },
    /// `dst = a op b` at `dst.bits`.
    Binary {
        /// The operation.
        op: BinOp,
        /// Written.
        dst: RegPart,
        /// Left operand.
        a: Value,
        /// Right operand.
        b: Value,
        /// What happens to the flags.
        flags: Flags,
    },
    /// The flags of `a - b` (`cmp`), nothing written.
    Compare {
        /// Left operand.
        a: Value,
        /// Right operand.
        b: Value,
    },
    /// An indirect jump to `target`.
    Jump {
        /// Where it goes.
        target: Value,
    },
    /// An indirect call to `target`. What the callee changes is not
    /// described: analyses apply their calling convention.
    Call {
        /// Where it goes.
        target: Value,
    },
    /// A conditional branch on the flags.
    Branch {
        /// When it is taken.
        cond: Cond,
    },
    /// Anything else. `writes` lists the registers it may change; `all` is
    /// true when that is not known (calls, unsupported instructions), and
    /// `flags` when it may change the flags.
    Other {
        /// Registers written.
        writes: Vec<Reg>,
        /// True if any register may change.
        all: bool,
        /// True if the flags may change.
        flags: bool,
    },
}

impl Effect {
    /// Nothing known: every register and the flags may change.
    pub const UNKNOWN: Effect = Effect::Other {
        writes: Vec::new(),
        all: true,
        flags: true,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negation_is_an_involution() {
        for c in [
            Cond::Eq,
            Cond::Ne,
            Cond::Below,
            Cond::BelowOrEqual,
            Cond::Above,
            Cond::AboveOrEqual,
            Cond::Other,
        ] {
            assert_eq!(c.negate().negate(), c);
        }
        assert_eq!(Cond::Above.negate(), Cond::BelowOrEqual);
    }
}
