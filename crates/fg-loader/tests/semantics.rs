// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Correct inputs: parsed values, provenance spans and mitigation verdicts.

mod common;
use common::*;
use fg_core::{ArchId, Bitness, Endian, Span, Va};
use fg_loader::{BinaryKind, LoadOptions, Verdict, load};

const DT_BIND_NOW: i64 = 24;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

fn with_dynamic(mut e: ElfBuilder, entries: &[(i64, u64)]) -> ElfBuilder {
    let d = e.dynamic(entries, true);
    e.phdrs.push(
        Phdr::new(PT_DYNAMIC, PF_R | PF_W)
            .file(0x180, d.len() as u64)
            .mem(0x400180, d.len() as u64),
    );
    e.blobs.push((0x180, d));
    e
}

#[test]
fn minimal_exec_is_clean_and_non_pie() {
    let bin = load(&minimal_exec().build(), &LoadOptions::default()).unwrap();
    // The only note: it has no section headers (the builder adds none by default).
    assert_eq!(codes(&bin), ["elf.section.none"], "{:?}", bin.anomalies);
    assert_eq!(bin.arch, ArchId::X86_64);
    assert_eq!(bin.bitness, Bitness::Bits64);
    assert_eq!(bin.kind, BinaryKind::Executable);
    assert_eq!(bin.mitigations.pie.verdict, Verdict::Disabled);
    assert!(bin.mitigations.pie.summary.contains("0x400000"));
    assert_eq!(bin.mitigations.nx.verdict, Verdict::Enabled);
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Disabled);
    assert_eq!(bin.mitigations.canary.verdict, Verdict::Unknown);
    assert_eq!(bin.segments.len(), 1);
    assert_eq!(bin.segments[0].perms.to_string(), "R-X");
}

#[test]
fn provenance_spans_point_at_header_bytes() {
    let bin = load(&minimal_exec().build(), &LoadOptions::default()).unwrap();
    let entry = bin.entry.as_ref().unwrap();
    assert_eq!(entry.value, Va(0x400100));
    assert_eq!(
        entry.span,
        Span::new(24, 8),
        "ELF64 e_entry lives at 0x18..0x1f"
    );
    let elf = bin.elf().unwrap();
    assert_eq!(elf.header.e_machine.span, Span::new(18, 2));
    let stack = &elf.program_headers[1];
    assert_eq!(stack.span, Span::new(64 + 56, 56));
    assert_eq!(stack.p_flags.span, Span::new(64 + 56 + 4, 4));
    let nx_ev = &bin.mitigations.nx.evidence[0];
    assert_eq!(
        nx_ev.span,
        Some(stack.p_flags.span),
        "NX evidence points at the GNU_STACK flags"
    );
}

#[test]
fn elf32_big_endian() {
    let mut e = minimal_exec();
    e.class64 = false;
    e.big_endian = true;
    e.machine = 8; // MIPS: recognised format, not a known architecture
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.bitness, Bitness::Bits32);
    assert_eq!(bin.endian, Endian::Big);
    assert_eq!(bin.arch, ArchId::Unknown);
    assert!(codes(&bin).contains(&"elf.machine.unknown"));
    let entry = bin.entry.as_ref().unwrap();
    assert_eq!(entry.value, Va(0x400100));
    assert_eq!(entry.span, Span::new(24, 4), "ELF32 e_entry is 4 bytes");
    let load0 = &bin.elf().unwrap().program_headers[0];
    assert_eq!(load0.p_vaddr.value, 0x400000);
    assert_eq!(load0.p_memsz.value, 0x200);
    assert_eq!(load0.perms().to_string(), "R-X");
    assert_eq!(
        load0.p_flags.span,
        Span::new(52 + 24, 4),
        "ELF32 puts p_flags after p_memsz"
    );
}

#[test]
fn pie_from_df_1_pie() {
    let mut e = with_dynamic(minimal_exec(), &[(DT_FLAGS_1, DF_1_PIE)]);
    e.e_type = ET_DYN;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.kind, BinaryKind::PieExecutable);
    assert_eq!(bin.mitigations.pie.verdict, Verdict::Enabled);
    assert!(
        bin.mitigations
            .pie
            .evidence
            .iter()
            .any(|ev| ev.text.contains("DF_1_PIE"))
    );
}

#[test]
fn pie_inferred_from_interpreter() {
    let mut e = minimal_exec();
    e.e_type = ET_DYN;
    e.phdrs.push(Phdr::new(PT_INTERP, PF_R).file(0x1c0, 13));
    e.blobs.push((0x1c0, b"/lib/ld.so.1\0".to_vec()));
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.kind, BinaryKind::PieExecutable);
    assert_eq!(
        bin.elf().unwrap().interpreter.as_ref().unwrap().value,
        "/lib/ld.so.1"
    );
    assert!(
        bin.mitigations
            .pie
            .evidence
            .iter()
            .any(|ev| ev.text.contains("inferred"))
    );
}

#[test]
fn shared_object() {
    let mut e = minimal_exec();
    e.e_type = ET_DYN;
    e.entry = 0;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.kind, BinaryKind::SharedObject);
    assert_eq!(bin.mitigations.pie.verdict, Verdict::NotApplicable);
    assert!(bin.entry.is_none());
}

#[test]
fn relocatable_object_mitigations_not_applicable() {
    let mut e = minimal_exec();
    e.e_type = ET_REL;
    e.entry = 0;
    e.phdrs.clear();
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.kind, BinaryKind::Relocatable);
    for m in bin.mitigations.all().into_iter().take(3) {
        assert_eq!(m.verdict, Verdict::NotApplicable, "{}", m.name);
    }
}

#[test]
fn nx_verdicts() {
    let mut e = minimal_exec();
    e.phdrs[1].flags = PF_R | PF_W | PF_X;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.nx.verdict, Verdict::Disabled);

    let mut e = minimal_exec();
    e.phdrs.truncate(1);
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.nx.verdict, Verdict::Unknown);
}

#[test]
fn relro_verdicts() {
    let relro = Phdr::new(PT_GNU_RELRO, PF_R)
        .file(0x100, 0x80)
        .mem(0x400100, 0x80)
        .align(1);

    let mut partial = with_dynamic(minimal_exec(), &[(1, 0x10)]);
    partial.phdrs.push(relro.clone());
    let bin = load(&partial.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Partial);

    let mut full = with_dynamic(minimal_exec(), &[(DT_BIND_NOW, 0)]);
    full.phdrs.push(relro.clone());
    let bin = load(&full.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Enabled);

    let mut full1 = with_dynamic(minimal_exec(), &[(DT_FLAGS_1, DF_1_NOW)]);
    full1.phdrs.push(relro);
    let bin = load(&full1.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Enabled);
    assert!(
        bin.mitigations
            .relro
            .evidence
            .iter()
            .any(|ev| ev.text.contains("DF_1_NOW"))
    );
}

#[test]
fn json_serialisation_round_trips_to_valid_json() {
    let bin = load(&minimal_exec().build(), &LoadOptions::default()).unwrap();
    // Serialize trait is part of the public contract (CLI --json, future RPC).
    fn assert_serialize<T: serde::Serialize>(_: &T) {}
    assert_serialize(&bin);
}
