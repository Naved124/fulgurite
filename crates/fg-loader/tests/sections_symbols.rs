//! Section headers, symbol tables and the verdicts that depend on them.

mod common;
use common::*;
use fg_core::{Span, Va};
use fg_loader::{LoadOptions, SymbolKind, SymbolTable, Verdict, load};

const STB_GLOBAL: u8 = 1;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const SHN_ABS: u16 = 0xfff1;

fn info(bind: u8, ty: u8) -> u8 {
    (bind << 4) | ty
}

/// A string table and the offset of each name in it.
fn strtab(names: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut out = vec![0u8];
    let mut offs = Vec::new();
    for n in names {
        offs.push(out.len() as u32);
        out.extend_from_slice(n.as_bytes());
        out.push(0);
    }
    (out, offs)
}

/// Executable with `.text` inside its LOAD, plus a symbol table of section type
/// `sym_type` holding `syms` (names are given; offsets resolved here).
fn with_symbols(sym_type: u32, syms: &[(&str, u8, u16, u64, u64)]) -> ElfBuilder {
    let mut e = minimal_exec();
    let names: Vec<&str> = syms.iter().map(|s| s.0).collect();
    let (strs, offs) = strtab(&names);
    let encoded: Vec<(u32, u8, u16, u64, u64)> = syms
        .iter()
        .zip(&offs)
        .map(|(s, &o)| (o, s.1, s.2, s.3, s.4))
        .collect();
    let table = e.symbols64(&encoded);
    let (str_off, sym_off) = (0x300u64, 0x400u64);
    e.blobs.push((str_off, strs.clone()));
    e.blobs.push((sym_off, table.clone()));
    e.sections = vec![
        Shdr::new(".text", SHT_PROGBITS)
            .flags(SHF_ALLOC | SHF_EXECINSTR)
            .addr(0x400000)
            .at(0, 0x200),
        Shdr::new(".strtab", SHT_STRTAB).at(str_off, strs.len() as u64),
        Shdr::new(".symtab", sym_type)
            .at(sym_off, table.len() as u64)
            .link(2, 1)
            .entsize(24),
    ];
    e
}

#[test]
fn static_symbols_are_parsed_with_provenance() {
    let e = with_symbols(
        SHT_SYMTAB,
        &[
            ("main", info(STB_GLOBAL, STT_FUNC), 1, 0x400100, 0x20),
            ("answer", info(0, STT_OBJECT), SHN_ABS, 42, 4),
            ("puts", info(STB_GLOBAL, STT_FUNC), 0, 0, 0),
        ],
    );
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let names: Vec<_> = bin.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".strtab", ".symtab", ".shstrtab"]);
    assert_eq!(bin.sections[0].va, Some(Va(0x400000)));
    assert!(bin.sections[0].perms.execute);

    assert_eq!(bin.symbols.len(), 4, "null symbol + 3");
    let main = &bin.symbols[1];
    assert_eq!(
        (main.name.as_str(), main.va, main.size),
        ("main", Va(0x400100), 0x20)
    );
    assert_eq!(main.kind, SymbolKind::Function);
    assert_eq!(main.table, SymbolTable::Static);
    assert!(main.defined);
    assert_eq!(main.defined_by, Span::new(0x400 + 24, 24));
    let elf = bin.elf().unwrap();
    let t = elf.symtab.as_ref().unwrap();
    assert_eq!(t.symbols[2].ndx_display(), "ABS");
    assert_eq!(t.symbols[3].ndx_display(), "UND");
    assert_eq!(
        t.symbols[1].name.as_ref().unwrap().span,
        Span::new(0x301, 4),
        "name 'main' at strtab+1"
    );
    assert!(!bin.symbols[3].defined);
    assert_eq!(
        bin.imports().count(),
        0,
        "static-table symbols are not run-time imports"
    );
}

#[test]
fn canary_and_fortify_from_dynamic_symbols() {
    let und = info(STB_GLOBAL, STT_FUNC);
    let e = with_symbols(
        SHT_DYNSYM,
        &[
            ("__stack_chk_fail", und, 0, 0, 0),
            ("__memcpy_chk", und, 0, 0, 0),
            ("memcpy", und, 0, 0, 0),
            ("printf", und, 0, 0, 0),
        ],
    );
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.imports().count(), 4);
    assert_eq!(bin.mitigations.canary.verdict, Verdict::Enabled);
    assert!(
        bin.mitigations.canary.evidence[0]
            .text
            .contains("__stack_chk_fail")
    );
    let f = &bin.mitigations.fortify;
    assert_eq!(f.verdict, Verdict::Enabled);
    assert!(
        f.summary.contains("1 of 2"),
        "memcpy counts once (fortified); printf is the other: {}",
        f.summary
    );

    let e = with_symbols(SHT_DYNSYM, &[("printf", und, 0, 0, 0)]);
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.canary.verdict, Verdict::Disabled);
    assert_eq!(bin.mitigations.fortify.verdict, Verdict::Disabled);
}

#[test]
fn no_symbols_means_unknown_not_disabled() {
    let bin = load(&minimal_exec().build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.canary.verdict, Verdict::Unknown);
    assert_eq!(bin.mitigations.fortify.verdict, Verdict::Unknown);
    assert!(codes(&bin).contains(&"elf.section.none"));
}

#[test]
fn elf32_sections_and_names() {
    let mut e = minimal_exec();
    e.class64 = false;
    e.sections = vec![
        Shdr::new(".text", SHT_PROGBITS)
            .flags(SHF_ALLOC | SHF_EXECINSTR)
            .addr(0x400000)
            .at(0, 0x200),
    ];
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert_eq!(bin.sections[0].name, ".text");
    assert_eq!(bin.elf().unwrap().section_headers[1].span.len, 40);
}

fn shoff(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[40..48].try_into().unwrap())
}

#[test]
fn section_header_escapes() {
    let mut e = with_symbols(SHT_SYMTAB, &[]);
    e.shnum_override = Some(0);
    e.sh0_size = 5; // null + .text .strtab .symtab .shstrtab
    e.shstrndx_override = Some(0xffff);
    e.sh0_link = 4;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    let c = codes(&bin);
    assert!(c.contains(&"elf.section.extended_count"), "{c:?}");
    assert!(c.contains(&"elf.section.extended_shstrndx"), "{c:?}");
    assert_eq!(bin.sections.len(), 4);
    assert_eq!(bin.sections[3].name, ".shstrtab");
}

#[test]
fn hostile_section_tables() {
    let base = || {
        with_symbols(
            SHT_SYMTAB,
            &[("main", info(STB_GLOBAL, STT_FUNC), 1, 0x400100, 1)],
        )
    };

    let mut e = base();
    e.shstrndx_override = Some(99);
    assert!(
        codes(&load(&e.build(), &LoadOptions::default()).unwrap())
            .contains(&"elf.section.shstrndx_invalid")
    );

    let mut e = base();
    e.shentsize_override = Some(20);
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert!(codes(&bin).contains(&"elf.section.entsize_too_small"));
    assert!(bin.sections.is_empty());

    let mut e = base();
    e.shnum_override = Some(200);
    assert!(
        codes(&load(&e.build(), &LoadOptions::default()).unwrap())
            .contains(&"elf.section.table_truncated")
    );

    let mut bytes = base().build();
    let at = (shoff(&bytes) + 64) as usize; // section #1's sh_name
    bytes[at..at + 4].copy_from_slice(&0xffffu32.to_le_bytes());
    assert!(
        codes(&load(&bytes, &LoadOptions::default()).unwrap())
            .contains(&"elf.section.name_invalid")
    );
}

#[test]
fn sections_are_checked_against_segments() {
    let mut e = minimal_exec();
    e.phdrs[0].flags = PF_R; // the LOAD is not executable
    e.sections = vec![
        Shdr::new(".text", SHT_PROGBITS)
            .flags(SHF_ALLOC | SHF_EXECINSTR)
            .addr(0x400000)
            .at(0, 0x100),
        Shdr::new(".far", SHT_PROGBITS)
            .flags(SHF_ALLOC)
            .addr(0x900000)
            .at(0x100, 0x10),
        Shdr::new(".moved", SHT_PROGBITS)
            .flags(SHF_ALLOC)
            .addr(0x400100)
            .at(0x50, 0x10),
        Shdr::new(".huge", SHT_PROGBITS).at(0x10_0000, 0x100),
        Shdr::new(".bss", SHT_NOBITS)
            .flags(SHF_ALLOC | SHF_WRITE)
            .addr(0x900000)
            .at(0x200, 0x1000),
    ];
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    let c = codes(&bin);
    for code in [
        "elf.section.exec_mismatch",
        "elf.section.outside_segments",
        "elf.section.offset_mismatch",
        "elf.section.past_eof",
    ] {
        assert!(c.contains(&code), "missing {code} in {c:?}");
    }
    assert_eq!(
        c.iter()
            .filter(|x| **x == "elf.section.outside_segments")
            .count(),
        1,
        "zero-filled .bss is not compared with file-backed segments"
    );
}

#[test]
fn hostile_symbol_tables() {
    // String table link that is not a string table.
    let mut e = with_symbols(SHT_SYMTAB, &[("main", info(STB_GLOBAL, STT_FUNC), 1, 0, 0)]);
    e.sections[2].link = 1;
    assert!(
        codes(&load(&e.build(), &LoadOptions::default()).unwrap())
            .contains(&"elf.symtab.strtab_invalid")
    );

    // Table that claims far more entries than the file holds.
    let mut e = with_symbols(SHT_SYMTAB, &[("main", info(STB_GLOBAL, STT_FUNC), 1, 0, 0)]);
    e.sections[2].size = 24 * 100_000;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert!(codes(&bin).contains(&"elf.symtab.truncated"));

    // Name offset outside the string table.
    let mut e = minimal_exec();
    let (strs, _) = strtab(&["main"]);
    let table = e.symbols64(&[(0xdead, info(STB_GLOBAL, STT_FUNC), 1, 0, 0)]);
    e.blobs.push((0x300, strs.clone()));
    e.blobs.push((0x400, table.clone()));
    e.sections = vec![
        Shdr::new(".strtab", SHT_STRTAB).at(0x300, strs.len() as u64),
        Shdr::new(".symtab", SHT_SYMTAB)
            .at(0x400, table.len() as u64)
            .link(1, 1)
            .entsize(24),
    ];
    assert!(
        codes(&load(&e.build(), &LoadOptions::default()).unwrap())
            .contains(&"elf.symtab.name_invalid")
    );
}

#[test]
fn dynamic_symbol_table_pointing_nowhere() {
    let mut e = minimal_exec();
    let d = e.dynamic(&[(6, 0xdead_0000), (5, 0x400300), (10, 16)], true);
    e.phdrs.push(
        Phdr::new(PT_DYNAMIC, PF_R | PF_W)
            .file(0x180, d.len() as u64)
            .mem(0x400180, d.len() as u64),
    );
    e.blobs.push((0x180, d));
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert!(codes(&bin).contains(&"elf.dynamic.unmapped"));
    assert!(bin.elf().unwrap().dynsym.is_none());
}

#[test]
fn every_truncation_of_a_file_with_sections_is_safe() {
    let full = with_symbols(
        SHT_DYNSYM,
        &[("__stack_chk_fail", info(STB_GLOBAL, STT_FUNC), 0, 0, 0)],
    )
    .build();
    for len in 0..=full.len() {
        let _ = load(&full[..len], &LoadOptions::default());
    }
}
