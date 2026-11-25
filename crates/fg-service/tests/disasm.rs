// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Listing semantics on small binaries built here: labels, seeds, overlapping
//! labels, invalid and cut-off bytes, operand names, PLT stub names, every
//! target kind, object files, and the errors. Skipped (with a note) where gcc
//! is not installed.

#![allow(missing_docs)]

use fg_service::Session;
use fg_service::core::Va;
use fg_service::disasm::{DisasmError, InsnLine, Line, Options, Target};
use fg_service::ir::{DecodeError, Flow, Syntax, TokenKind, tokens_text};
use fg_service::loader::SeedKind;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

const LISTING_S: &str = r#".intel_syntax noprefix
.text
.globl f
.type f, @function
f:
    mov eax, 0x11223344
.globl inside
.set inside, f+1
    call g
    ret
.size f, .-f
.globl g
.hidden g
.type g, @function
g:
    lea rax, [rip+obj]
    jmp qword ptr [rip+obj+8]
    .byte 0x06
    ret
.size g, .-g
.globl tail
tail:
    .byte 0xe8, 0x00
.data
.globl obj
.hidden obj
.type obj, @object
obj: .quad 0, 0
.size obj, 16
"#;

const PROGRAM_C: &str = r#"#include <stdio.h>
#include <stdlib.h>
static int helper(int x) { return x * 3; }
int main(int argc, char **argv) {
    (void)argv;
    puts("hello");
    if (argc > 3) abort();
    return helper(argc);
}
"#;

struct Fixtures {
    /// `LISTING_S` linked as a shared library with entry point `f`.
    listing_so: PathBuf,
    /// The same, as an unlinked object.
    listing_o: PathBuf,
    /// `PROGRAM_C` with lazy binding and IBT: `.plt` + `.plt.sec`.
    program_ibt: PathBuf,
    /// `PROGRAM_C` with lazy binding and no IBT: classic `.plt` entries.
    program_plain: PathBuf,
}

fn fixtures() -> Option<&'static Fixtures> {
    static F: OnceLock<Option<Fixtures>> = OnceLock::new();
    F.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("disasm-semantics");
        let _ = std::fs::create_dir_all(&dir);
        let s = dir.join("listing.s");
        let c = dir.join("program.c");
        std::fs::write(&s, LISTING_S).ok()?;
        std::fs::write(&c, PROGRAM_C).ok()?;
        let f = Fixtures {
            listing_so: dir.join("listing.so"),
            listing_o: dir.join("listing.o"),
            program_ibt: dir.join("program_ibt"),
            program_plain: dir.join("program_plain"),
        };
        let ok = |args: &[&str], src: &PathBuf, out: &PathBuf| {
            Command::new("gcc")
                .args(args)
                .arg(src)
                .arg("-o")
                .arg(out)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        let built = ok(&["-shared", "-nostdlib", "-Wl,-e,f"], &s, &f.listing_so)
            && ok(&["-c"], &s, &f.listing_o)
            && ok(
                &["-O1", "-fcf-protection=full", "-Wl,-z,lazy"],
                &c,
                &f.program_ibt,
            )
            && ok(
                &["-O1", "-fcf-protection=none", "-Wl,-z,lazy"],
                &c,
                &f.program_plain,
            );
        if !built {
            eprintln!("note: gcc could not build the listing fixtures; tests skipped");
        }
        built.then_some(f)
    })
    .as_ref()
}

fn listing(path: &PathBuf, target: &Target) -> Vec<Line> {
    Session::open(path)
        .unwrap()
        .disassemble(target, Options::default())
        .unwrap()
}

fn insns(lines: &[Line]) -> Vec<&InsnLine> {
    lines
        .iter()
        .filter_map(|l| match l {
            Line::Insn(i) => Some(i),
            _ => None,
        })
        .collect()
}

fn text(i: &InsnLine) -> String {
    tokens_text(&i.tokens)
}

fn symbol_va(path: &PathBuf, name: &str) -> u64 {
    let s = Session::open(path).unwrap();
    s.binary()
        .symbols
        .iter()
        .find(|x| x.name == name && x.defined)
        .unwrap_or_else(|| panic!("no symbol {name}"))
        .va
        .0
}

#[test]
fn labels_overlaps_bad_bytes_and_names() {
    let Some(fx) = fixtures() else { return };
    let f = symbol_va(&fx.listing_so, "f");
    let g = symbol_va(&fx.listing_so, "g");
    let obj = symbol_va(&fx.listing_so, "obj");
    let lines = listing(&fx.listing_so, &Target::Section(".text".into()));
    // Region first, then the label of f, which is also the entry point.
    assert!(
        matches!(&lines[0], Line::Region { name, start, .. } if name == ".text" && start.0 == f)
    );
    assert_eq!(
        lines[1],
        Line::Label {
            va: Va(f),
            names: vec!["f".into()],
            seeds: vec![SeedKind::Entry],
        }
    );
    // The mov is shown whole and flagged: `inside` starts in its second byte,
    // and decoding restarts there.
    let Line::Insn(mov) = &lines[2] else {
        panic!("{:?}", lines[2])
    };
    assert_eq!(
        (text(mov).as_str(), mov.overlaps_label),
        ("mov eax,0x11223344", true)
    );
    assert!(
        matches!(&lines[3], Line::Label { va, names, .. } if va.0 == f + 1 && names == &["inside"])
    );
    let Line::Insn(next) = &lines[4] else {
        panic!()
    };
    assert_eq!(next.insn.va.0, f + 1);
    // g: the RIP-relative operands are named after the object they reach.
    let all = insns(&lines);
    let lea = all.iter().find(|i| i.insn.va.0 == g).unwrap();
    let comment = lea.tokens.last().unwrap();
    assert_eq!(comment.kind, TokenKind::Comment);
    assert_eq!(comment.text, format!("  # {obj:#x} <obj>"));
    assert_eq!(comment.value, Some(obj));
    let jmp = all.iter().find(|i| i.insn.va.0 == g + 7).unwrap();
    assert_eq!(jmp.insn.flow, Flow::IndirectJump);
    assert!(text(jmp).ends_with(&format!("# {:#x} <obj+0x8>", obj + 8)));
    // An invalid byte is skipped alone; decoding resumes right after it.
    let bad: Vec<&Line> = lines
        .iter()
        .filter(|l| matches!(l, Line::Bad { .. }))
        .collect();
    assert!(matches!(
        bad[0],
        Line::Bad { va, bytes, error: DecodeError::Invalid { .. } } if va.0 == g + 13 && bytes == &[0x06]
    ));
    assert!(
        all.iter()
            .any(|i| i.insn.va.0 == g + 14 && text(i) == "ret")
    );
    // The section ends in the middle of a call.
    let tail = symbol_va(&fx.listing_so, "tail");
    assert_eq!(
        *bad[1],
        Line::Bad {
            va: Va(tail),
            bytes: vec![0xe8, 0x00],
            error: DecodeError::Truncated,
        }
    );
}

#[test]
fn every_target_kind() {
    let Some(fx) = fixtures() else { return };
    let f = symbol_va(&fx.listing_so, "f");
    let g = symbol_va(&fx.listing_so, "g");
    // A count of instructions from an address, crossing labels.
    let lines = listing(
        &fx.listing_so,
        &Target::At {
            va: Va(f),
            count: 3,
        },
    );
    assert_eq!(insns(&lines).len(), 3);
    assert!(matches!(lines[0], Line::Label { .. }), "labels are kept");
    // A range: the lea and the jmp of g, nothing after.
    let lines = listing(
        &fx.listing_so,
        &Target::Range {
            start: Va(g),
            end: Va(g + 13),
        },
    );
    let all = insns(&lines);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].insn.va.0, g + 7);
    // A range that ends inside an instruction reports it as cut off.
    let lines = listing(
        &fx.listing_so,
        &Target::Range {
            start: Va(g),
            end: Va(g + 3),
        },
    );
    assert!(
        matches!(&lines[1], Line::Bad { error: DecodeError::Truncated, bytes, .. } if bytes.len() == 3)
    );
    // A function by name ends at its symbol size.
    let lines = listing(&fx.listing_so, &Target::Symbol("g".into()));
    let all = insns(&lines);
    assert_eq!(all.first().unwrap().insn.va.0, g);
    assert_eq!(all.last().unwrap().insn.va.0, g + 14);
    // AT&T syntax.
    let s = Session::open(&fx.listing_so).unwrap();
    let att = s
        .disassemble(
            &Target::Symbol("g".into()),
            Options::with_syntax(Syntax::Att),
        )
        .unwrap();
    assert!(text(insns(&att)[0]).starts_with("lea 0x"));
    // Errors.
    assert_eq!(
        s.disassemble(&Target::Section(".nope".into()), Options::default()),
        Err(DisasmError::NoSuchSection(".nope".into()))
    );
    assert_eq!(
        s.disassemble(&Target::Symbol("nope".into()), Options::default()),
        Err(DisasmError::NoSuchSymbol("nope".into()))
    );
    assert_eq!(
        s.disassemble(
            &Target::At {
                va: Va(0x7777_0000),
                count: 4
            },
            Options::default()
        ),
        Err(DisasmError::Unmapped(Va(0x7777_0000)))
    );
}

#[test]
fn object_files_list_each_section_from_zero_without_labels() {
    let Some(fx) = fixtures() else { return };
    let lines = listing(&fx.listing_o, &Target::CodeSections);
    assert!(
        matches!(&lines[0], Line::Region { name, start, .. } if name == ".text" && start.0 == 0)
    );
    assert!(!lines.iter().any(|l| matches!(l, Line::Label { .. })));
    let all = insns(&lines);
    // Unrelocated: the call targets the next instruction, and nothing is named.
    assert_eq!(all[1].insn.flow, Flow::Call { target: Va(0xa) });
    assert!(
        all.iter()
            .all(|i| i.tokens.iter().all(|t| t.kind != TokenKind::Comment))
    );
    // Without labels nothing restarts: the call after the mov is decoded.
    assert_eq!(text(all[1]), "call 0xa");
}

#[test]
fn plt_stubs_and_imports_are_named() {
    let Some(fx) = fixtures() else { return };
    for path in [&fx.program_ibt, &fx.program_plain] {
        let session = Session::open(path).unwrap();
        let lines = session
            .disassemble(&Target::CodeSections, Options::default())
            .unwrap();
        // A label `puts@plt` exists, at the stub that jumps through puts' slot.
        let stub = lines
            .iter()
            .find_map(|l| match l {
                Line::Label { va, names, .. } if names.iter().any(|n| n == "puts@plt") => {
                    Some(va.0)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("{}: no puts@plt label", path.display()));
        let all = insns(&lines);
        let jump = all
            .iter()
            .filter(|i| i.insn.va.0 >= stub)
            .find(|i| i.insn.flow == Flow::IndirectJump)
            .unwrap();
        assert!(text(jump).contains("[puts@"), "{}", text(jump));
        // main calls the stub by name, and the entry point is labelled.
        let main = symbol_va(path, "main");
        let call = all
            .iter()
            .filter(|i| i.insn.va.0 >= main)
            .find(|i| i.insn.flow == Flow::Call { target: Va(stub) })
            .unwrap();
        assert!(text(call).ends_with("<puts@plt>"), "{}", text(call));
        let entry = session.binary().entry.as_ref().unwrap().value;
        assert!(lines.iter().any(|l| matches!(
            l,
            Line::Label { va, seeds, .. } if *va == entry && seeds.contains(&SeedKind::Entry)
        )));
        // Constructors from .init_array are labelled as such.
        assert!(lines.iter().any(|l| matches!(
            l,
            Line::Label { seeds, .. } if seeds.contains(&SeedKind::InitArray)
        )));
    }
}

#[test]
fn unsupported_architectures_are_reported() {
    let Some(fx) = fixtures() else { return };
    // The same file claiming to be RISC-V (e_machine 0xf3), which has no decoder.
    let mut bytes = std::fs::read(&fx.listing_so).unwrap();
    bytes[0x12] = 0xf3;
    bytes[0x13] = 0;
    let s = Session::from_bytes("riscv.so", bytes.into(), &Default::default()).unwrap();
    assert!(s.arch().is_none());
    assert_eq!(
        s.disassemble(&Target::CodeSections, Options::default()),
        Err(DisasmError::UnsupportedArch(s.binary().arch))
    );
}

#[test]
fn streaming_stops_when_asked() {
    let Some(fx) = fixtures() else { return };
    let s = Session::open(&fx.program_ibt).unwrap();
    let mut seen = 0;
    s.disassemble_each(&Target::CodeSections, Options::default(), &mut |_| {
        seen += 1;
        if seen == 5 {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    })
    .unwrap();
    assert_eq!(seen, 5);
}
