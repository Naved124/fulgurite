// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Functions of Arm's pseudocode that the generated tables call: alias
//! preferences, logical immediates, floating-point immediates, system
//! instruction kinds. Written from the pseudocode in the A64 ISA release.

use crate::tables::{SYS_OP, SYS_OP128, SYSL_OP, SysKind};

/// Sign-extends the low `bits` bits of `v`.
pub(crate) fn sext(v: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (v << shift) >> shift
}

/// `DecodeBitMasks(immN, imms, immr, TRUE, M).wmask`: the value of a logical
/// immediate, or `None` for a reserved encoding.
pub(crate) fn decode_bit_masks(n: u32, imms: u32, immr: u32, m: u32) -> Option<u64> {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined & 0x7e == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    let esize = 1u32 << len;
    if esize > m {
        return None;
    }
    let levels = esize - 1;
    if imms & levels == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let welem: u64 = if s + 1 == 64 {
        !0
    } else {
        (1u64 << (s + 1)) - 1
    };
    let emask: u64 = if esize == 64 { !0 } else { (1u64 << esize) - 1 };
    let rotated = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize - r))) & emask
    };
    let mut out = 0u64;
    let mut i = 0;
    while i < m {
        out |= rotated << i;
        i += esize;
    }
    if m < 64 {
        out &= (1u64 << m) - 1;
    }
    Some(out)
}

/// `MoveWidePreferred()`: the ORR immediate is also a single MOVZ/MOVN, so
/// `orr` is shown rather than `mov`.
///
/// The pseudocode's halfword test misses some rotations (for `0xf801ffff`,
/// which `movn w0, #0x7fe, lsl #16` builds, it says no); this tests what the
/// function's description says, as GNU objdump and LLVM do.
pub(crate) fn move_wide_preferred(sf: u32, n: u32, imms: u32, immr: u32) -> bool {
    let width = if sf == 1 { 64 } else { 32 };
    if sf == 1 && n != 1 {
        return false;
    }
    if sf == 0 && (n != 0 || imms & 0x20 != 0) {
        return false;
    }
    let Some(v) = decode_bit_masks(n, imms, immr, width) else {
        return false;
    };
    let mask = if width == 64 { !0u64 } else { 0xffff_ffff };
    let one_halfword = |x: u64| (0..width / 16).any(|h| x & !(0xffffu64 << (16 * h)) & mask == 0);
    one_halfword(v) || one_halfword(!v & mask)
}

/// `BFXPreferred()`: UBFX/SBFX rather than a more specific alias of UBFM/SBFM.
pub(crate) fn bfx_preferred(sf: u32, uns: u32, imms: u32, immr: u32) -> bool {
    if imms < immr {
        return false;
    }
    if imms == (sf << 5) | 0x1f {
        return false;
    }
    if immr == 0 {
        if sf == 0 && (imms == 0b000111 || imms == 0b001111) {
            return false;
        }
        if sf == 1 && uns == 0 && matches!(imms, 0b000111 | 0b001111 | 0b011111) {
            return false;
        }
    }
    true
}

/// `SVEMoveMaskPreferred()`: the DUPM immediate is not also a DUP immediate.
pub(crate) fn sve_move_mask_preferred(imm13: u32) -> bool {
    let Some(imm) = decode_bit_masks((imm13 >> 12) & 1, imm13 & 0x3f, (imm13 >> 6) & 0x3f, 64)
    else {
        return false;
    };
    let bits = |hi: u32, lo: u32| -> u64 {
        let width = hi - lo + 1;
        let v = imm >> lo;
        if width == 64 {
            v
        } else {
            v & ((1u64 << width) - 1)
        }
    };
    let zero = |hi, lo| bits(hi, lo) == 0;
    let ones = |hi: u32, lo: u32| {
        let width = hi - lo + 1;
        bits(hi, lo) == if width == 64 { !0 } else { (1u64 << width) - 1 }
    };
    let halves = bits(63, 32) == bits(31, 0);
    let quarters = halves && bits(31, 16) == bits(15, 0);
    if bits(7, 0) != 0 {
        if zero(63, 7) || ones(63, 7) {
            return false;
        }
        if halves && (zero(31, 7) || ones(31, 7)) {
            return false;
        }
        if quarters && (zero(15, 7) || ones(15, 7)) {
            return false;
        }
        if quarters && bits(15, 8) == bits(7, 0) {
            return false;
        }
    } else {
        if zero(63, 15) || ones(63, 15) {
            return false;
        }
        if halves && (zero(31, 15) || ones(31, 15)) {
            return false;
        }
        if quarters {
            return false;
        }
    }
    true
}

/// SVE shift immediate `tsz:imm` (`low` bits below `tsz`): the element size is
/// 8 << HighestSetBit(tsz); a right shift is `2 * esize - value`, a left shift
/// `value - esize`.
pub(crate) fn tsz_shift(v: u32, low: u32, right: bool) -> i64 {
    let tsz = v >> low;
    if tsz == 0 {
        return 0;
    }
    let esize = 8i64 << (31 - tsz.leading_zeros());
    if right {
        2 * esize - i64::from(v)
    } else {
        i64::from(v) - esize
    }
}

/// SVE element index `imm:tsz` (`tsz` is the low `tsz_bits` bits): the index
/// sits above the lowest set bit of `tsz`.
pub(crate) fn tsz_index(v: u32, tsz_bits: u32) -> i64 {
    let tsz = v & ((1 << tsz_bits) - 1);
    if tsz == 0 {
        return 0;
    }
    i64::from(v >> (tsz.trailing_zeros() + 1))
}

/// `'aaaaaaaabbbbbbbb...hhhhhhhh'`: each bit of `imm8` widened to a byte.
pub(crate) fn byte_mask(imm8: u32) -> i64 {
    let mut v = 0u64;
    for i in 0..8 {
        if imm8 >> i & 1 != 0 {
            v |= 0xff << (8 * i);
        }
    }
    v as i64
}

/// Number of set bits.
pub(crate) fn bit_count(v: u32) -> i64 {
    i64::from(v.count_ones())
}

fn lookup(table: &[(u16, u16, SysKind)], op1: u32, crn: u32, crm: u32, op2: u32) -> SysKind {
    let key = ((op1 << 11) | (crn << 7) | (crm << 3) | op2) as u16;
    table
        .iter()
        .find(|(mask, value, _)| key & mask == *value)
        .map_or(SysKind::Sys, |e| e.2)
}

/// `SysOp()`: which system instruction a SYS encoding is.
pub(crate) fn sys_op(op1: u32, crn: u32, crm: u32, op2: u32) -> SysKind {
    lookup(&SYS_OP, op1, crn, crm, op2)
}

/// `SysOp128()`: which system instruction a SYSP encoding is.
pub(crate) fn sys_op128(op1: u32, crn: u32, crm: u32, op2: u32) -> SysKind {
    lookup(&SYS_OP128, op1, crn, crm, op2)
}

/// `SysLOp()`: which system instruction a SYSL encoding is.
pub(crate) fn sysl_op(op1: u32, crn: u32, crm: u32, op2: u32) -> SysKind {
    lookup(&SYSL_OP, op1, crn, crm, op2)
}

/// `VFPExpandImm()` for a 64-bit result, as a value.
pub(crate) fn fp_imm(imm8: u32) -> f64 {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    // exponent: NOT(b6):Replicate(b6):imm8<5:4>, i.e. -3..=4 around a bias.
    let b6 = (imm8 >> 6) & 1;
    let e = ((imm8 >> 4) & 3) as i32;
    let exp = if b6 == 1 { e - 3 } else { e + 1 };
    let frac = f64::from(16 + (imm8 & 0xf)) / 16.0;
    sign * frac * 2f64.powi(exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_masks() {
        // and x0, x1, #0xff : N=1 immr=0 imms=7
        assert_eq!(decode_bit_masks(1, 7, 0, 64), Some(0xff));
        // and w0, w1, #0x80000000: N=0 immr=1 imms=0
        assert_eq!(decode_bit_masks(0, 0, 1, 32), Some(0x8000_0000));
        // 0x5555555555555555: 2-bit elements 01
        assert_eq!(
            decode_bit_masks(0, 0b111100, 0, 64),
            Some(0x5555_5555_5555_5555)
        );
        // all ones is reserved
        assert_eq!(decode_bit_masks(1, 0b111111, 0, 64), None);
        // N=1 in a 32-bit instruction is reserved
        assert_eq!(decode_bit_masks(1, 7, 0, 32), None);
    }

    #[test]
    fn fp_immediates() {
        assert_eq!(fp_imm(0x70), 1.0);
        assert_eq!(fp_imm(0x00), 2.0);
        assert_eq!(fp_imm(0xf0), -1.0);
        assert_eq!(fp_imm(0x60), 0.5);
        assert_eq!(fp_imm(0x3f), 31.0);
        assert_eq!(fp_imm(0x40), 0.125);
    }

    #[test]
    fn sign_extension() {
        assert_eq!(sext(0x7f, 7), -1);
        assert_eq!(sext(0x3f, 7), 63);
    }
}
