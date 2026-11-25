// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! What instructions do to registers: the jump-table and address-pair forms
//! exactly, and what anything else writes.

#![allow(missing_docs)]

use fg_arch_arm64::ARM64;
use fg_core::Va;
use fg_ir::{Addr, Arch, Effect, Index, Mode, Reg, RegPart, Value};

const PC: u64 = 0x41_0004;

fn effect(w: u32) -> String {
    let insn = ARM64
        .decode(&w.to_le_bytes(), Va(PC), Mode::Native)
        .unwrap();
    named(&ARM64.effect(&insn))
}

fn r(p: RegPart) -> String {
    ARM64.reg_name(p)
}

fn x(reg: Reg) -> String {
    r(RegPart { reg, bits: 64 })
}

fn addr(a: &Addr) -> String {
    let mut t = Vec::new();
    if let Some(b) = a.base {
        t.push(x(b));
    }
    if let Some(Index { reg, signed, shift }) = a.index {
        t.push(format!(
            "{}{}<<{shift}",
            if signed { "s" } else { "" },
            r(reg)
        ));
    }
    t.push(format!("{:#x}", a.disp));
    t.join("+")
}

fn value(v: &Value) -> String {
    match v {
        Value::Imm { value } => format!("{value:#x}"),
        Value::Reg {
            part,
            signed,
            shift,
        } => format!("{}{}<<{shift}", if *signed { "s" } else { "" }, r(*part)),
        Value::Address { addr: a } => format!("&[{}]", addr(a)),
        Value::Load {
            addr: a,
            bytes,
            signed,
        } => format!("{}{bytes}[{}]", if *signed { "s" } else { "" }, addr(a)),
    }
}

fn named(e: &Effect) -> String {
    match e {
        Effect::Move { dst, src } => format!("{} = {}", r(*dst), value(src)),
        Effect::Binary {
            op,
            dst,
            a,
            b,
            flags,
        } => format!("{} = {} {op:?} {} ({flags:?})", r(*dst), value(a), value(b)),
        Effect::Compare { a, b } => format!("cmp {} {}", value(a), value(b)),
        Effect::Jump { target } => format!("jmp {}", value(target)),
        Effect::Call { target } => format!("call {}", value(target)),
        Effect::Branch { cond } => format!("branch {cond:?}"),
        Effect::Other { writes, all, flags } => {
            let w: Vec<String> = writes.iter().map(|&g| x(g)).collect();
            format!("other {w:?} all={all} flags={flags}")
        }
        _ => format!("{e:?}"),
    }
}

#[test]
fn a_jump_table_as_gcc_emits_it() {
    // cmp w0, #7; b.hi; adrp x1, T; add x1, x1, #0x10; ldrb w1, [x1, w0, uxtw];
    // adr x0, base; add x0, x0, w1, sxtb #2; br x0
    assert_eq!(effect(0x7100_1c1f), "cmp w0<<0 0x7");
    assert_eq!(effect(0x5400_0048), "branch Above");
    assert_eq!(effect(0x9000_0001), "x1 = &[0x410000]");
    assert_eq!(effect(0x9100_4021), "x1 = x1<<0 Add 0x10 (Kept)");
    assert_eq!(effect(0x3860_4821), "w1 = 1[x1+w0<<0+0x0]");
    assert_eq!(effect(0x1000_0040), "x0 = &[0x41000c]");
    assert_eq!(effect(0x8b21_8800), "x0 = x0<<0 Add sw1<<2 (Kept)");
    assert_eq!(effect(0xd61f_0000), "jmp x0<<0");
    // blr x8: a call through the register a table entry was loaded into.
    assert_eq!(effect(0xd63f_0100), "call x8<<0");
}

#[test]
fn loads_moves_and_compares() {
    // ldr w1, [x1, x0, lsl #2]; ldr x17, [x16, #8] (a PLT stub's slot)
    assert_eq!(effect(0xb860_7821), "w1 = 4[x1+x0<<2+0x0]");
    assert_eq!(effect(0xf940_0611), "x17 = 8[x16+0x8]");
    // mov x1, x2; movz w3, #5; mov x0, sp (add x0, sp, #0)
    assert_eq!(effect(0xaa02_03e1), "x1 = x2<<0");
    assert_eq!(effect(0x5280_00a3), "w3 = 0x5");
    assert_eq!(effect(0x9100_03e0), "x0 = sp<<0 Add 0x0 (Kept)");
    // subs w2, w2, #1 sets the flags as a compare; b.ls, b.lo, b.ge.
    assert_eq!(effect(0x7100_0442), "w2 = w2<<0 Sub 0x1 (Compare)");
    assert_eq!(effect(0x5400_0049), "branch BelowOrEqual");
    assert_eq!(effect(0x5400_0043), "branch Below");
    assert_eq!(effect(0x5400_004a), "branch Other");
}

#[test]
fn anything_else_says_what_it_writes() {
    // stp x29, x30, [sp, #-16]! writes back the stack pointer.
    assert_eq!(effect(0xa9bf_7bfd), r#"other ["sp"] all=false flags=false"#);
    // ldp x19, x20, [sp, #16] writes both.
    assert_eq!(
        effect(0xa941_53f3),
        r#"other ["x19", "x20"] all=false flags=false"#
    );
    // str x0, [x1] writes nothing; mul x0, x1, x2 writes x0.
    assert_eq!(effect(0xf900_0020), "other [] all=false flags=false");
    assert_eq!(effect(0x9b02_7c20), r#"other ["x0"] all=false flags=false"#);
    // ands xzr, x0, #1 (tst) changes only the flags; fcmp s0, s1 too.
    assert_eq!(effect(0xf240_001f), "other [] all=false flags=true");
    assert_eq!(effect(0x1e21_2000), "other [] all=false flags=true");
    // A SIMD add writes no general register; an SVE one is not described.
    assert_eq!(effect(0x4ea1_8400), "other [] all=false flags=false");
    assert_eq!(effect(0x04a1_0000), "other [] all=true flags=true");
}

#[test]
fn every_word_has_an_effect() {
    // A sweep over the top bits with fixed register fields: no panic.
    for hi in 0..=0xffffu32 {
        let w = (hi << 16) | 0x1234;
        if let Ok(i) = ARM64.decode(&w.to_le_bytes(), Va(PC), Mode::Native) {
            let _ = ARM64.effect(&i);
        }
    }
}

fn mem(w: u32) -> String {
    let insn = ARM64
        .decode(&w.to_le_bytes(), Va(PC), Mode::Native)
        .unwrap();
    ARM64
        .mem_addr(&insn)
        .map_or("none".to_string(), |(a, access)| {
            format!("{access:?} {}", addr(&a))
        })
}

#[test]
fn memory_operands_of_loads_and_stores() {
    // Unsigned scaled, unscaled, pre-indexed and post-indexed offsets
    // (a post-index uses the base before the update).
    assert_eq!(mem(0xf904_8101), "Write x8+0x900"); // str x1, [x8, #2304]
    assert_eq!(mem(0xb81f_c101), "Write x8+0xfffffffffffffffc"); // stur w1, [x8, #-4]
    assert_eq!(mem(0xf81f_0fe1), "Write sp+0xfffffffffffffff0"); // str x1, [sp, #-16]!
    assert_eq!(mem(0xf840_8441), "Read x2+0x0"); // ldr x1, [x2], #8
    // Register offsets, shifted and sign-extended.
    assert_eq!(mem(0xb823_7841), "Write x2+x3<<2+0x0"); // str w1, [x2, x3, lsl #2]
    assert_eq!(mem(0x3863_c841), "Read x2+sw3<<0+0x0"); // ldrb w1, [x2, w3, sxtw]
    // Pairs scale by the register size; a Q register is 16 bytes.
    assert_eq!(mem(0xa9bf_7bfd), "Write sp+0xfffffffffffffff0"); // stp x29, x30, [sp, #-16]!
    assert_eq!(mem(0xad41_0400), "Read x0+0x20"); // ldp q0, q1, [x0, #32]
    assert_eq!(mem(0x3d80_0400), "Write x0+0x10"); // str q0, [x0, #16]
    assert_eq!(mem(0xa83f_8861), "Write x3+0xfffffffffffffff8"); // stnp x1, x2, [x3, #-8]
    // Exclusive and atomic accesses: the base alone.
    assert_eq!(mem(0xc85f_fc20), "Read x1+0x0"); // ldaxr x0, [x1]
    assert_eq!(mem(0xb820_0041), "ReadWrite x2+0x0"); // ldadd w0, w1, [x2]
    // A literal load is PC-relative; no memory operand at all.
    assert_eq!(mem(0x5800_0040), "Read 0x41000c"); // ldr x0, #8 (at 0x410004)
    assert_eq!(mem(0x9100_0420), "none"); // add x0, x1, #1
}
