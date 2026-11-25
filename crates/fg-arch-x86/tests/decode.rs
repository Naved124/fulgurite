// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Decoder semantics: exact control flow, memory operands, immediates, text and
//! error kinds for chosen encodings, then sweeps over the opcode space and over
//! random bytes that check the invariants every caller relies on.

#![allow(missing_docs)]

use fg_arch_x86::{MAX_INSN_LEN, X86, X86_32, X86_64};
use fg_core::Va;
use fg_ir::{
    Access, Addr, Arch, DecodeError, Effect, Flow, Index, Insn, Mode, RegPart, Syntax, TokenKind,
    Value, tokens_text,
};

const VA: u64 = 0x1000;

fn d64(bytes: &[u8]) -> Insn {
    X86_64.decode(bytes, Va(VA), Mode::Native).unwrap()
}

fn d32(bytes: &[u8]) -> Insn {
    X86_32.decode(bytes, Va(VA), Mode::Native).unwrap()
}

fn intel(arch: &X86, i: &Insn) -> String {
    tokens_text(&arch.format(i, Syntax::Intel))
}

fn att(arch: &X86, i: &Insn) -> String {
    tokens_text(&arch.format(i, Syntax::Att))
}

#[test]
fn text_reads_like_objdump_intel() {
    for (bytes, text) in [
        (&[0x48, 0x89, 0xe5][..], "mov rbp,rsp"),
        (
            &[0xc7, 0x45, 0xfc, 0, 0, 0, 0],
            "mov dword ptr [rbp-0x4],0x0",
        ),
        (
            &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0],
            "mov rax,qword ptr fs:[0x28]",
        ),
        (&[0x48, 0x83, 0xec, 0x80], "sub rsp,0xffffffffffffff80"),
        (
            &[0x48, 0x8d, 0x3d, 0xd1, 0xfe, 0xff, 0xff],
            "lea rdi,[rip-0x12f]",
        ),
        (&[0x0f, 0x1f, 0x40, 0x00], "nop dword ptr [rax+0x0]"),
        (
            &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
            "nop word ptr cs:[rax+rax*1+0x0]",
        ),
        (
            &[0x42, 0x80, 0x3c, 0x28, 0x00],
            "cmp byte ptr [rax+r13*1],0x0",
        ),
        (&[0xf3, 0x0f, 0x1e, 0xfa], "endbr64"),
        (&[0x3e, 0xff, 0xe0], "notrack jmp rax"),
        (
            &[0xf2, 0xff, 0x25, 0x12, 0x2f, 0, 0],
            "bnd jmp qword ptr [rip+0x2f12]",
        ),
        (
            &[0xf2, 0xf0, 0x83, 0x07, 0x01],
            "xacquire lock add dword ptr [rdi],0x1",
        ),
        (
            &[0xf3, 0x48, 0xa5],
            "rep movsq qword ptr [rdi],qword ptr [rsi]",
        ),
        (
            &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            "mov rax,0x1122334455667788",
        ),
        (&[0x48, 0x69, 0xd2, 0xd0, 0, 0, 0], "imul rdx,0xd0"),
        (
            &[0x62, 0xf1, 0x75, 0x48, 0xfe, 0x46, 0x40],
            "vpaddd zmm0,zmm1,zmmword ptr [rsi+0x1000]",
        ),
        (
            &[0x62, 0xf1, 0x75, 0xd9, 0xfe, 0x06],
            "vpaddd zmm0{k1}{z},zmm1,dword ptr [rsi]{1to16}",
        ),
    ] {
        assert_eq!(intel(&X86_64, &d64(bytes)), text, "{bytes:02x?}");
    }
}

#[test]
fn att_syntax() {
    for (bytes, text) in [
        (&[0x48, 0x89, 0xe5][..], "mov %rsp,%rbp"),
        (&[0x0f, 0x4f, 0x03], "cmovg (%rbx),%eax"),
        (&[0xc7, 0x45, 0xfc, 0, 0, 0, 0], "movl $0x0,-0x4(%rbp)"),
        (&[0xff, 0x25, 0x12, 0x2f, 0, 0], "jmpq *0x2f12(%rip)"),
    ] {
        assert_eq!(att(&X86_64, &d64(bytes)), text, "{bytes:02x?}");
    }
    let far = d32(&[0xea, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00]);
    assert_eq!(att(&X86_32, &far), "ljmp $0x10,$0x1000");
}

#[test]
fn tokens_are_typed() {
    let i = d64(&[0xe8, 0xe2, 0xfe, 0xff, 0xff]);
    let t = X86_64.format(&i, Syntax::Intel);
    assert_eq!(t[0].kind, TokenKind::Mnemonic);
    let target = t.iter().find(|t| t.kind == TokenKind::Address).unwrap();
    assert_eq!((target.text.as_str(), target.value), ("0xee7", Some(0xee7)));
    let i = d64(&[0x48, 0x8b, 0x45, 0xf8]);
    let tokens = X86_64.format(&i, Syntax::Intel);
    let regs: Vec<&str> = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Register)
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(regs, vec!["rax", "rbp"]);
    // A far pointer is written selector:offset.
    let far = d32(&[0xea, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00]);
    assert_eq!(intel(&X86_32, &far), "jmp far 0x10:0x1000");
}

#[test]
fn control_flow() {
    let cases: &[(&[u8], Flow)] = &[
        (&[0x90], Flow::Next),
        (
            &[0xeb, 0x10],
            Flow::Jump {
                target: Va(VA + 0x12),
            },
        ),
        (
            &[0xe9, 0x00, 0x01, 0, 0],
            Flow::Jump {
                target: Va(VA + 0x105),
            },
        ),
        (&[0x74, 0xfe], Flow::Branch { target: Va(VA) }),
        (
            &[0x0f, 0x85, 0x10, 0, 0, 0],
            Flow::Branch {
                target: Va(VA + 0x16),
            },
        ),
        (&[0xe3, 0x02], Flow::Branch { target: Va(VA + 4) }),
        (&[0xe2, 0x02], Flow::Branch { target: Va(VA + 4) }),
        (
            &[0xc7, 0xf8, 0x10, 0, 0, 0],
            Flow::Branch {
                target: Va(VA + 0x16),
            },
        ),
        (&[0xe8, 0x00, 0, 0, 0], Flow::Call { target: Va(VA + 5) }),
        (&[0xff, 0xd0], Flow::IndirectCall),
        (&[0xff, 0x15, 0x10, 0, 0, 0], Flow::IndirectCall),
        (&[0xff, 0xe0], Flow::IndirectJump),
        (&[0xff, 0x24, 0xc5, 0, 0x20, 0, 0], Flow::IndirectJump),
        (&[0xc3], Flow::Return),
        (&[0xc2, 0x08, 0x00], Flow::Return),
        (&[0xcc], Flow::Interrupt),
        (&[0xcd, 0x80], Flow::Interrupt),
        (&[0x0f, 0x05], Flow::Interrupt),
        (&[0x0f, 0x0b], Flow::Trap),
        (&[0xf4], Flow::Trap),
    ];
    for (bytes, flow) in cases {
        assert_eq!(d64(bytes).flow, *flow, "{bytes:02x?}");
    }
    // A 16-bit operand size truncates the target to 16 bits.
    assert_eq!(
        X86_64
            .decode(&[0xe9, 0x00, 0x00], Va(0x1_2340), Mode::X86_16)
            .unwrap()
            .flow,
        Flow::Jump { target: Va(0x2343) }
    );
    // Far jumps leave the segment: no target in this address space.
    assert_eq!(
        d32(&[0xea, 0, 0x10, 0, 0, 0x10, 0]).flow,
        Flow::IndirectJump
    );
    assert!(Flow::Interrupt.falls_through() && !Flow::Trap.falls_through());
}

#[test]
fn memory_operands() {
    // RIP-relative: the address is resolved from the next instruction.
    let m = d64(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0]).mem.unwrap();
    assert_eq!(m.addr, Some(Va(VA + 7 + 0x10)));
    assert!(m.pc_relative && !m.segment_based);
    assert_eq!((m.displacement, m.size, m.access), (0x10, 8, Access::Read));
    // Negative RIP displacement.
    let m = d64(&[0x48, 0x8d, 0x3d, 0xd1, 0xfe, 0xff, 0xff])
        .mem
        .unwrap();
    assert_eq!(m.addr, Some(Va(VA + 7 - 0x12f)));
    assert_eq!((m.displacement, m.access), (-0x12f, Access::Address));
    // Absolute through SIB without base or index, and the 64-bit moffs form.
    let m = d64(&[0x8b, 0x04, 0x25, 0x28, 0x40, 0x60, 0]).mem.unwrap();
    assert_eq!((m.addr, m.pc_relative), (Some(Va(0x60_4028)), false));
    let m = d64(&[0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])
        .mem
        .unwrap();
    assert_eq!(m.addr, Some(Va(0x1122_3344_5566_7788)));
    // A negative disp32 in 64-bit absolute addressing is sign-extended.
    let m = d64(&[0x8b, 0x04, 0x25, 0x00, 0x10, 0x00, 0x80])
        .mem
        .unwrap();
    assert_eq!(m.addr, Some(Va(0xffff_ffff_8000_1000)));
    // fs: offsets are not addresses.
    let m = d64(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0])
        .mem
        .unwrap();
    assert_eq!(
        (m.addr, m.segment_based, m.displacement),
        (None, true, 0x28)
    );
    // Register-based: displacement only.
    let m = d64(&[0xc7, 0x45, 0xfc, 0, 0, 0, 0]).mem.unwrap();
    assert_eq!(
        (m.addr, m.displacement, m.access),
        (None, -4, Access::Write)
    );
    let m = d64(&[0x01, 0x07]).mem.unwrap();
    assert_eq!(m.access, Access::ReadWrite);
    // cmov always reads its source; only the register write is conditional.
    let m = d64(&[0x0f, 0x4f, 0x03]).mem.unwrap();
    assert_eq!((m.access, m.conditional), (Access::Read, false));
    // Masked AVX-512 store: the write may not happen.
    let m = d64(&[0x62, 0xf1, 0x7c, 0x49, 0x11, 0x07]).mem.unwrap();
    assert_eq!((m.access, m.conditional, m.size), (Access::Write, true, 64));
    // AVX-512 compressed disp8 (0x40 * 64) and a plain disp32.
    let m = d64(&[0x62, 0xf1, 0x75, 0x48, 0xfe, 0x46, 0x40])
        .mem
        .unwrap();
    assert_eq!(m.displacement, 0x1000);
    let m = d64(&[0x48, 0x8b, 0x80, 0, 0xf0, 0xff, 0xff]).mem.unwrap();
    assert_eq!(m.displacement, -0x1000);
    // 32- and 16-bit address sizes sign-extend at their own width.
    let m = d32(&[0x8b, 0x45, 0xfc]).mem.unwrap();
    assert_eq!((m.displacement, m.size), (-4, 4));
    let m = d32(&[0x8b, 0x80, 0x00, 0xf0, 0xff, 0xff]).mem.unwrap();
    assert_eq!(m.displacement, -0x1000);
    let m = X86_64
        .decode(&[0x8b, 0x46, 0xfe], Va(VA), Mode::X86_16)
        .unwrap()
        .mem
        .unwrap();
    assert_eq!((m.displacement, m.size), (-2, 2));
    // 32-bit absolute address: zero-extended.
    let m = d32(&[0xa1, 0x00, 0x00, 0x00, 0x80]).mem.unwrap();
    assert_eq!(m.addr, Some(Va(0x8000_0000)));
    // Implicit memory (push, string instructions) is not an explicit operand.
    assert_eq!(d64(&[0x50]).mem, None);
    assert_eq!(d64(&[0xf3, 0x48, 0xa5]).mem, None);
}

#[test]
fn immediates_and_nops() {
    assert_eq!(d64(&[0xb8, 0x78, 0x56, 0x34, 0x12]).imm, Some(0x1234_5678));
    // Sign-extended to the operand size.
    assert_eq!(d64(&[0x6a, 0xf0]).imm, Some(0xffff_ffff_ffff_fff0));
    assert_eq!(d32(&[0x6a, 0xf0]).imm, Some(0xffff_fff0));
    assert_eq!(d32(&[0x68, 0x00, 0x20, 0x40, 0x00]).imm, Some(0x40_2000));
    assert_eq!(d64(&[0x48, 0x89, 0xe5]).imm, None);
    for nop in [
        &[0x90][..],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
    ] {
        assert!(d64(nop).nop, "{nop:02x?}");
    }
    assert!(!d64(&[0xf3, 0x90]).nop, "pause is not padding");
    assert!(!d64(&[0x87, 0xc0]).nop, "xchg eax,eax zero-extends rax");
}

#[test]
fn errors_and_modes() {
    let e = |a: &X86, b: &[u8]| a.decode(b, Va(VA), Mode::Native).unwrap_err();
    assert_eq!(e(&X86_64, &[]), DecodeError::Truncated);
    assert_eq!(e(&X86_64, &[0x48]), DecodeError::Truncated);
    assert_eq!(e(&X86_64, &[0xe8, 0x00]), DecodeError::Truncated);
    // Invalid in 64-bit mode, even as the last byte available.
    assert_eq!(e(&X86_64, &[0x06]), DecodeError::Invalid { len: 1 });
    assert!(matches!(
        e(&X86_64, &[0xd6, 0x90]),
        DecodeError::Invalid { .. }
    ));
    assert_eq!(intel(&X86_32, &d32(&[0xd6])), "salc");
    // Longer than 15 bytes raises #UD.
    assert!(matches!(
        e(&X86_64, &[0x66; 16]),
        DecodeError::Invalid { .. }
    ));
    // 40 is a REX prefix in 64-bit mode and `inc eax` in 32-bit mode.
    assert_eq!(intel(&X86_32, &d32(&[0x40])), "inc eax");
    assert_eq!(e(&X86_64, &[0x40]), DecodeError::Truncated);
    // A REX that is not directly before the opcode is ignored, as on hardware.
    let i = d64(&[0x47, 0x46, 0x28, 0x32]);
    assert_eq!(
        (i.len(), intel(&X86_64, &i).as_str()),
        (4, "sub byte ptr [rdx],r14b")
    );
    // Explicit modes.
    let i = X86_64
        .decode(&[0xb8, 0x34, 0x12], Va(VA), Mode::X86_16)
        .unwrap();
    assert_eq!(
        (i.mode, intel(&X86_64, &i).as_str()),
        (Mode::X86_16, "mov ax,0x1234")
    );
    let i = X86_32
        .decode(&[0x48, 0x89, 0xe5], Va(VA), Mode::X86_64)
        .unwrap();
    assert_eq!(intel(&X86_32, &i), "mov rbp,rsp");
    assert_eq!(X86::for_arch(fg_core::ArchId::Aarch64), None);
}

/// The registers in an effect, by name.
fn named(arch: &X86, e: &Effect) -> String {
    let r = |p: &RegPart| arch.reg_name(*p);
    let addr = |a: &Addr| {
        let mut t = Vec::new();
        if let Some(b) = a.base {
            t.push(r(&RegPart { reg: b, bits: 64 }));
        }
        if let Some(Index { reg, signed, shift }) = a.index {
            t.push(format!(
                "{}{}<<{shift}",
                if signed { "s" } else { "" },
                r(&reg)
            ));
        }
        t.push(format!("{:#x}", a.disp));
        t.join("+")
    };
    let v = |v: &Value| match v {
        Value::Imm { value } => format!("{value:#x}"),
        Value::Reg {
            part,
            signed,
            shift,
        } => {
            format!("{}{}<<{shift}", if *signed { "s" } else { "" }, r(part))
        }
        Value::Address { addr: a } => format!("&[{}]", addr(a)),
        Value::Load {
            addr: a,
            bytes,
            signed,
        } => {
            format!("{}{bytes}[{}]", if *signed { "s" } else { "" }, addr(a))
        }
    };
    match e {
        Effect::Move { dst, src } => format!("{} = {}", r(dst), v(src)),
        Effect::Binary {
            op,
            dst,
            a,
            b,
            flags,
        } => {
            format!("{} = {} {op:?} {} ({flags:?})", r(dst), v(a), v(b))
        }
        Effect::Compare { a, b } => format!("cmp {} {}", v(a), v(b)),
        Effect::Jump { target } => format!("jmp {}", v(target)),
        Effect::Call { target } => format!("call {}", v(target)),
        Effect::Branch { cond } => format!("branch {cond:?}"),
        Effect::Other { writes, all, flags } => {
            let w: Vec<String> = writes
                .iter()
                .map(|&g| r(&RegPart { reg: g, bits: 64 }))
                .collect();
            format!("other {w:?} all={all} flags={flags}")
        }
        _ => format!("{e:?}"),
    }
}

#[test]
fn effects() {
    let e64 = |b: &[u8]| named(&X86_64, &X86_64.effect(&d64(b)));
    let e32 = |b: &[u8]| named(&X86_32, &X86_32.effect(&d32(b)));
    // A position-independent jump table, as gcc emits it.
    assert_eq!(e64(&[0x83, 0xff, 0x07]), "cmp edi<<0 0x7");
    assert_eq!(e64(&[0x77, 0x10]), "branch Above");
    assert_eq!(e64(&[0x48, 0x8d, 0x15, 0x10, 0, 0, 0]), "rdx = &[0x1017]");
    assert_eq!(e64(&[0x48, 0x63, 0x04, 0x82]), "rax = s4[rdx+rax<<2+0x0]");
    assert_eq!(
        e64(&[0x48, 0x01, 0xd0]),
        "rax = rax<<0 Add rdx<<0 (Changed)"
    );
    assert_eq!(e64(&[0xff, 0xe0]), "jmp rax<<0");
    // An absolute one, and the 32-bit writes that zero-extend the index.
    assert_eq!(
        e64(&[0xff, 0x24, 0xc5, 0x00, 0x20, 0x40, 0x00]),
        "jmp 8[rax<<3+0x402000]"
    );
    // Indirect calls say where they go; a direct call is not described.
    assert_eq!(e64(&[0xff, 0xd0]), "call rax<<0");
    assert_eq!(
        e64(&[0xff, 0x14, 0xc5, 0x00, 0x20, 0x40, 0x00]),
        "call 8[rax<<3+0x402000]"
    );
    assert_eq!(e64(&[0xe8, 0, 0, 0, 0]), "other [] all=true flags=true");
    assert_eq!(e64(&[0x89, 0xc0]), "eax = eax<<0");
    assert_eq!(e64(&[0x0f, 0xb6, 0xc0]), "eax = al<<0");
    assert_eq!(e64(&[0x48, 0x98]), "rax = seax<<0");
    assert_eq!(e64(&[0x83, 0xe8, 0x03]), "eax = eax<<0 Sub 0x3 (Compare)");
    assert_eq!(e64(&[0x83, 0xf8, 0xff]), "cmp eax<<0 0xffffffff");
    assert_eq!(e64(&[0x76, 0x10]), "branch BelowOrEqual");
    assert_eq!(e64(&[0x7f, 0x10]), "branch Other");
    // Anything else: what it writes.
    assert_eq!(e64(&[0x31, 0xc0]), r#"other ["rax"] all=false flags=true"#);
    assert_eq!(e64(&[0xe2, 0xfe]), r#"other ["rcx"] all=false flags=false"#);
    assert_eq!(e64(&[0x89, 0x07]), "other [] all=false flags=false");
    assert_eq!(e64(&[0x88, 0xe0]), r#"other ["rax"] all=false flags=false"#);
    assert_eq!(e64(&[0xe8, 0, 0, 0, 0]), "other [] all=true flags=true");
    assert_eq!(e64(&[0xeb, 0x10]), "other [] all=false flags=false");
    assert_eq!(
        e64(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]),
        r#"other ["rax"] all=false flags=false"#
    );
    // 32-bit code: 32-bit addresses.
    assert_eq!(
        e32(&[0x8b, 0x84, 0x83, 0x10, 0, 0, 0]),
        "eax = 4[rbx+eax<<2+0x10]"
    );
}

/// Checks what callers rely on for any input: no panic, a length within
/// bounds, the bytes echoed back, the end address, and text in both syntaxes.
fn check_invariants(arch: &X86, mode: Mode, bytes: &[u8], va: u64) {
    match arch.decode(bytes, Va(va), mode) {
        Ok(i) => {
            let n = i.len() as usize;
            assert!(n >= 1 && n <= MAX_INSN_LEN.min(bytes.len()), "{bytes:02x?}");
            assert_eq!(i.bytes.as_slice(), &bytes[..n]);
            assert_eq!(i.end().0, va.wrapping_add(n as u64));
            let text = intel(arch, &i);
            assert!(!text.is_empty() && text != "(bad)", "{bytes:02x?}");
            assert!(!att(arch, &i).is_empty());
            // Re-decoding exactly the instruction's bytes gives the same result.
            assert_eq!(arch.decode(&bytes[..n], Va(va), mode).unwrap(), i);
            // Every instruction has an effect, if only an unknown one.
            let _ = arch.effect(&i);
        }
        Err(DecodeError::Invalid { len }) => {
            assert!(len >= 1 && usize::from(len) <= MAX_INSN_LEN, "{bytes:02x?}");
        }
        Err(DecodeError::Truncated) => assert!(bytes.len() < MAX_INSN_LEN, "{bytes:02x?}"),
        Err(e) => panic!("{e:?} for {bytes:02x?}"),
    }
}

#[test]
fn every_two_byte_opcode_prefix_holds_the_invariants() {
    // The first two bytes select legacy prefixes, REX/VEX/EVEX starts, every
    // one-byte opcode with every ModRM, and the 0F map. The tail completes
    // most instructions.
    let tail = [
        0x24, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
    ];
    for (arch, mode) in [
        (&X86_64, Mode::Native),
        (&X86_32, Mode::Native),
        (&X86_64, Mode::X86_16),
    ] {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let mut bytes = vec![a, b];
                bytes.extend_from_slice(&tail);
                check_invariants(arch, mode, &bytes, 0x7fff_fff0);
            }
        }
    }
}

#[test]
fn random_bytes_hold_the_invariants() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..60_000u32 {
        let len = (next() % 17) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        // Bias inputs towards EVEX, VEX and the 0F map, where most of the
        // decoding complexity lives.
        if let Some(first) = bytes.first_mut() {
            match round % 4 {
                0 => *first = 0x62,
                1 => *first = 0xc4,
                2 => *first = 0x0f,
                _ => {}
            }
        }
        let va = next();
        check_invariants(&X86_64, Mode::Native, &bytes, va);
        check_invariants(&X86_32, Mode::Native, &bytes, va & 0xffff_ffff);
    }
}

#[test]
fn memory_operands_whatever_the_access() {
    let m64 = |b: &[u8]| {
        X86_64
            .mem_addr(&d64(b))
            .map(|(a, _)| (a.base, a.index.map(|i| i.shift), a.disp))
    };
    let m32 = |b: &[u8]| {
        X86_32
            .mem_addr(&d32(b))
            .map(|(a, _)| (a.base, a.index.map(|i| i.shift), a.disp))
    };
    // The access is the decoder's: a store writes.
    assert_eq!(
        X86_64
            .mem_addr(&d64(&[0x89, 0x05, 0x10, 0, 0, 0]))
            .map(|(_, x)| x),
        Some(fg_ir::Access::Write)
    );
    // mov [rip + 0x10], eax: a store, its address resolved.
    let rip = m64(&[0x89, 0x05, 0x10, 0, 0, 0]).unwrap();
    assert_eq!((rip.0, rip.1), (None, None));
    // mov [4*rax + 0x404000], edx: an absolute array indexed by a register.
    assert_eq!(
        m64(&[0x89, 0x14, 0x85, 0x00, 0x40, 0x40, 0x00]).map(|a| (a.1, a.2)),
        Some((Some(2), 0x404000))
    );
    // mov dword [ebx + 0x20], 1 in 32-bit code (the GOT pointer of PIC code).
    assert!(m32(&[0xc7, 0x43, 0x20, 1, 0, 0, 0]).is_some_and(|a| a.0.is_some() && a.2 == 0x20));
    // No memory operand; an fs:-based one is not an address.
    assert_eq!(m64(&[0x89, 0xc0]), None);
    assert_eq!(m64(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]), None);
}
