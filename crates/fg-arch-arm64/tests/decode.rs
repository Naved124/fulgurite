// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Decoder semantics: text, tokens, control flow, memory operands, errors.
#![allow(missing_docs)]

use fg_arch_arm64::{
    ARM64, INSN_LEN, adrp, encoding_name, encodings, is_unpredictable, load_offset,
};
use fg_core::{ArchId, Va};
use fg_ir::{Access, Arch, DecodeError, Flow, Mode, Syntax, TokenKind, tokens_text};

const PC: u64 = 0x40_1000;

fn decode(word: u32) -> Result<fg_ir::Insn, DecodeError> {
    ARM64.decode(&word.to_le_bytes(), Va(PC), Mode::Native)
}

fn text(word: u32) -> String {
    let insn = decode(word).unwrap_or_else(|e| panic!("{word:08x}: {e}"));
    tokens_text(&ARM64.format(&insn, Syntax::Intel))
}

#[test]
fn module_facts() {
    assert_eq!(ARM64.id(), ArchId::Aarch64);
    assert_eq!(ARM64.max_insn_len(), 4);
    assert_eq!(ARM64.insn_alignment(), 4);
    assert_eq!(INSN_LEN, 4);
    assert!(encodings().count() > 4000);
    assert_eq!(encoding_name(0x8b02_0020), Some("ADD_64_addsub_shift"));
    assert_eq!(encoding_name(0xffff_ffff), None);
}

#[test]
fn exact_text() {
    let cases: &[(u32, &str)] = &[
        (0x8b02_0020, "add x0, x1, x2"),
        (0x9100_0420, "add x0, x1, #1"),
        (0x9140_0420, "add x0, x1, #1, lsl #12"),
        (0x9100_03e0, "mov x0, sp"),
        (0xaa01_03e0, "mov x0, x1"),
        (0x5280_0020, "mov w0, #1"),
        (0x1280_0000, "mov w0, #-1"),
        (0xb240_0fe0, "orr x0, xzr, #0xf"),
        (0x9240_1c20, "and x0, x1, #0xff"),
        (0xd65f_03c0, "ret"),
        (0xd61f_0220, "br x17"),
        (0xd63f_0200, "blr x16"),
        (0xd400_0001, "svc #0x0"),
        (0xd420_0000, "brk #0x0"),
        (0x0000_0000, "udf #0"),
        (0xd503_201f, "nop"),
        (0xf940_0020, "ldr x0, [x1]"),
        (0xf940_0420, "ldr x0, [x1, #8]"),
        (0xa9bf_7bfd, "stp x29, x30, [sp, #-16]!"),
        (0xa8c1_7bfd, "ldp x29, x30, [sp], #16"),
        (0xb863_6820, "ldr w0, [x1, x3]"),
        (0xf863_7820, "ldr x0, [x1, x3, lsl #3]"),
        (0xb863_c820, "ldr w0, [x1, w3, sxtw]"),
        (0x4e20_8400, "add v0.16b, v0.16b, v0.16b"),
        (0x0e21_1c20, "and v0.8b, v1.8b, v1.8b"),
        (0x1e60_1000, "fmov d0, #2.00000000"),
        (0xd53b_d040, "mrs x0, tpidr_el0"),
        (0xd53b_4200, "mrs x0, nzcv"),
        (0xc8df_fc20, "ldar x0, [x1]"),
        (0xd340_fc20, "lsr x0, x1, #0"),
        (0xd37c_ec20, "lsl x0, x1, #4"),
        (0x9340_7c20, "sxtw x0, w1"),
        (0x1a82_5451, "cinc w17, w2, mi"),
        (0x6b25_49bf, "cmp w13, w5, uxtw #2"),
        (0x4b39_425f, "sub wsp, w18, w25"),
        (0xd503_233f, "paciasp"),
        (0xd503_241f, "bti"),
        (0xd503_245f, "bti c"),
        // PSTATE immediates: PM's CRm is 001x and its value is CRm<0>.
        (0xd501_421f, "msr pm, #0"),
        (0xd501_431f, "msr pm, #1"),
        (0xd501_401f, "msr allint, #0"),
        (0xd501_411f, "msr allint, #1"),
        // System instruction registers: left out at XZR only when the
        // operation reads none (Registers.json), never dropped when encoded.
        (0xd508_7100, "ic ialluis, x0"),
        (0xd508_711f, "ic ialluis"),
        (0xd508_871f, "tlbi vmalle1"),
        (0xd508_831f, "tlbi vmalle1is"),
        (0xd508_873f, "tlbi vae1, xzr"),
        (0xd50b_753f, "ic ivau, xzr"),
        (0xd508_c1ff, "gic cdeoi"),
        (0xd508_c17f, "gic cdaff, xzr"),
        (0xd548_813f, "tlbip vae1os, xzr, xzr"),
        (0xd548_8120, "tlbip vae1os, x0, x1"),
        // An alias whose template has no register is preferred only at Rt 31.
        (0xd508_779f, "gcspushx"),
        (0xd508_7780, "sys #0, c7, c7, #4, x0"),
        (0xd508_c01f, "gsb sys"),
        (0xd508_c000, "sys #0, c12, c0, #0, x0"),
        (0xd509_729f, "brb iall"),
        (0xd509_7280, "sys #1, c7, c2, #4, x0"),
        // Operations Registers.json names but the XML's SysOp() leaves out.
        (0xd50b_74a0, "dc zgbva, x0"),
        (0xd50b_7b00, "dc cvaoc, x0"),
        (0xd50c_8240, "tlbi vmallws2e1is, x0"),
        (0xd50c_825f, "tlbi vmallws2e1is"),
        // PLBI: the JSON alone describes it.
        (0xd508_a11f, "plbi vmalle1os"),
        (0xd508_a120, "plbi perme1os, x0"),
        (0xd508_a13f, "plbi perme1os, xzr"),
    ];
    for &(word, want) in cases {
        assert_eq!(text(word), want, "{word:08x}");
    }
}

#[test]
fn branch_targets_are_absolute() {
    assert_eq!(text(0x9400_0001), format!("bl {:#x}", PC + 4));
    assert_eq!(text(0x17ff_ffff), format!("b {:#x}", PC - 4));
    assert_eq!(text(0x5400_0040), format!("b.eq {:#x}", PC + 8));
    assert_eq!(text(0xb400_0040), format!("cbz x0, {:#x}", PC + 8));
    assert_eq!(text(0x3600_0040), format!("tbz w0, #0, {:#x}", PC + 8));
    assert_eq!(text(0x9000_0010), format!("adrp x16, {:#x}", PC & !0xfff));
    assert_eq!(
        text(0xb000_0010),
        format!("adrp x16, {:#x}", (PC & !0xfff) + 0x1000)
    );
    assert_eq!(text(0x1000_0000), format!("adr x0, {PC:#x}"));
    assert_eq!(text(0x5800_0040), format!("ldr x0, {:#x}", PC + 8));
}

#[test]
fn tokens_are_typed() {
    let insn = decode(0x9400_0001).unwrap();
    let tokens = ARM64.format(&insn, Syntax::Intel);
    assert_eq!(tokens[0].kind, TokenKind::Mnemonic);
    assert_eq!(tokens[0].text, "bl");
    let target = tokens
        .iter()
        .find(|t| t.kind == TokenKind::Address)
        .unwrap();
    assert_eq!(target.value, Some(PC + 4));

    let tokens = ARM64.format(&decode(0x9100_0420).unwrap(), Syntax::Att);
    let regs: Vec<&str> = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Register)
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(regs, ["x0", "x1"]);
    let num = tokens.iter().find(|t| t.kind == TokenKind::Number).unwrap();
    assert_eq!(num.value, Some(1));

    // Mnemonics with a condition are one token.
    let tokens = ARM64.format(&decode(0x5400_0040).unwrap(), Syntax::Intel);
    assert_eq!(tokens[0].text, "b.eq");
}

#[test]
fn control_flow() {
    let flow = |w| decode(w).unwrap().flow;
    assert_eq!(flow(0x8b02_0020), Flow::Next);
    assert_eq!(flow(0x1400_0002), Flow::Jump { target: Va(PC + 8) });
    assert_eq!(flow(0x9400_0001), Flow::Call { target: Va(PC + 4) });
    assert_eq!(flow(0x5400_0040), Flow::Branch { target: Va(PC + 8) });
    assert_eq!(flow(0xb400_0040), Flow::Branch { target: Va(PC + 8) });
    assert_eq!(flow(0x3600_0040), Flow::Branch { target: Va(PC + 8) });
    assert_eq!(flow(0xd61f_0220), Flow::IndirectJump);
    assert_eq!(flow(0xd63f_0200), Flow::IndirectCall);
    assert_eq!(flow(0xd65f_03c0), Flow::Return);
    assert_eq!(flow(0xd65f_0bff), Flow::Return); // retaa
    assert_eq!(flow(0xd69f_03e0), Flow::Return); // eret
    assert_eq!(flow(0xd400_0001), Flow::Interrupt); // svc
    assert_eq!(flow(0xd420_0000), Flow::Trap); // brk
    assert_eq!(flow(0x0000_0000), Flow::Trap); // udf
    assert!(decode(0xd503_201f).unwrap().nop);
    assert!(!decode(0x8b02_0020).unwrap().nop);
}

#[test]
fn memory_operands() {
    let adrp = decode(0x9000_0010).unwrap().mem.unwrap();
    assert_eq!(adrp.addr, Some(Va(PC & !0xfff)));
    assert_eq!(adrp.access, Access::Address);
    assert!(adrp.pc_relative);

    let adr = decode(0x1000_0020).unwrap().mem.unwrap();
    assert_eq!(adr.addr, Some(Va(PC + 4)));

    let lit = decode(0x5800_0040).unwrap().mem.unwrap();
    assert_eq!(
        (lit.addr, lit.size, lit.access),
        (Some(Va(PC + 8)), 8, Access::Read)
    );
    let lit32 = decode(0x1800_0040).unwrap().mem.unwrap(); // ldr w0, literal
    assert_eq!(lit32.size, 4);
    let litq = decode(0x9c00_0040).unwrap().mem.unwrap(); // ldr q0, literal
    assert_eq!(litq.size, 16);
    let prfm = decode(0xd800_0040).unwrap().mem.unwrap();
    assert_eq!(prfm.access, Access::Address);

    // Register-based operands have no address.
    assert_eq!(decode(0xf940_0020).unwrap().mem, None);
    assert_eq!(decode(0x9100_0420).unwrap().imm, Some(1));
}

#[test]
fn errors_and_modes() {
    let bytes = 0x8b02_0020u32.to_le_bytes();
    assert_eq!(
        ARM64.decode(&bytes[..3], Va(PC), Mode::Native),
        Err(DecodeError::Truncated)
    );
    assert_eq!(
        ARM64.decode(&bytes, Va(PC), Mode::X86_64),
        Err(DecodeError::UnsupportedMode)
    );
    // Unallocated, reserved field values, and decode-time UNDEFINED.
    for word in [
        0xffff_ffffu32,
        0x0001_0000,             // udf space with nonzero bits 16-31: unallocated
        0x8bc0_0020,             // add (shifted register) with shift = 11 (reserved)
        0x0b00_fc20,             // add w0, w1, w0, lsl #63: shift amount >= 32 is UNDEFINED
        0x1240_0000 | (1 << 22), // and w-form with N = 1
        0x0e20_8400 | (3 << 22), // add v.1d (size 11, Q 0): reserved arrangement
    ] {
        assert!(
            decode(word).is_err(),
            "{word:08x} decoded as {:?}",
            decode(word).map(|i| text_of(&i))
        );
    }
    // Extra bytes are ignored: the instruction is always four bytes.
    let mut long = 0x8b02_0020u32.to_le_bytes().to_vec();
    long.extend([0xff; 4]);
    assert_eq!(ARM64.decode(&long, Va(PC), Mode::Native).unwrap().len(), 4);
}

fn text_of(insn: &fg_ir::Insn) -> String {
    tokens_text(&ARM64.format(insn, Syntax::Intel))
}

#[test]
fn constrained_unpredictable() {
    // ldp x0, x0, [x1]: both destinations the same register.
    assert!(is_unpredictable(0xa940_0020));
    assert!(!is_unpredictable(0xa940_0420)); // ldp x0, x1, [x1]
    // ldr x0, [x0], #8: post-index writeback to the loaded register.
    assert!(is_unpredictable(0xf840_8400));
    assert!(!is_unpredictable(0xf840_8420)); // ldr x0, [x1], #8
    // The words still decode.
    assert!(decode(0xa940_0020).is_ok());
    // ldxr with Rs not 0b11111 ("should be one" bits): decoded, as hardware does.
    assert_eq!(text(0x8841_7c20), "ldxr w0, [x1]");
}

/// Every word of a coarse grid plus pseudo-random words: decoding never
/// panics, is deterministic, keeps four bytes, and every decoded word prints.
#[test]
fn decode_sweep() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut decoded = 0;
    for i in 0..400_000u32 {
        let word = if i < 65_536 {
            i << 16 | (i & 0xffff).wrapping_mul(0x9e37) >> 16
        } else {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u32
        };
        let Ok(insn) = decode(word) else { continue };
        decoded += 1;
        assert_eq!(insn.len(), 4);
        let t = text_of(&insn);
        assert!(!t.is_empty() && t != "(bad)", "{word:08x}");
        assert_eq!(decode(word).unwrap(), insn, "{word:08x}");
        assert_eq!(text_of(&decode(word).unwrap()), t);
    }
    assert!(decoded > 100_000, "only {decoded} words decoded");
}

/// One word of every encoding (its fixed bits, zeros elsewhere, then ones):
/// each decodes to that encoding or is rejected by its own checks.
#[test]
fn every_encoding_is_reachable() {
    let mut reached = 0;
    let mut total = 0;
    for e in encodings() {
        total += 1;
        let free = !e.mask;
        let words = [
            e.value,
            e.value | (free & 0x5555_5555),
            e.value | (free & 0xaaaa_aaaa),
            e.value | free,
        ];
        if words
            .iter()
            .any(|&w| encoding_name(w) == Some(e.name) && decode(w).is_ok())
        {
            reached += 1;
        }
    }
    // A few encodings only accept field values these four fills miss.
    assert!(
        reached * 100 >= total * 97,
        "{reached} of {total} encodings reached"
    );
}

#[test]
fn address_pairs() {
    // adrp x16, +0x10 pages; ldr x17, [x16, #0xf88]
    assert_eq!(adrp(0xb000_0090, PC), Some((16, (PC & !0xfff) + 0x11000)));
    assert_eq!(adrp(0x9000_0010, PC), Some((16, PC & !0xfff)));
    // The most negative page offset: immhi:immlo = -0x100000 pages (-4 GiB).
    assert_eq!(
        adrp(0x9080_0010, PC),
        Some((16, (PC & !0xfff).wrapping_sub(0x1_0000_0000)))
    );
    assert_eq!(adrp(0x1000_0000, PC), None); // adr
    assert_eq!(load_offset(0xf947_c611), Some((16, 0xf88)));
    assert_eq!(load_offset(0xb940_0420), Some((1, 4)));
    assert_eq!(load_offset(0x9100_0420), None); // add
}
