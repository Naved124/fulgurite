//! PE loader semantics on synthetic images: exact values, exact byte spans, and
//! every mitigation verdict.

mod common;
use common::pe::*;
use fg_core::{FileOffset, Span, Va};
use fg_loader::pe::{DebugContent, ResourceName, UnwindInfo};
use fg_loader::{
    BinaryKind, Format, LoadOptions, LoadedBinary, RelocKind, SeedKind, SymbolKind, SymbolTable,
    Verdict, load,
};

const BASE: u64 = 0x1_4000_0000;

fn ld(bytes: &[u8]) -> LoadedBinary {
    load(bytes, &LoadOptions::default()).expect("loads")
}

fn codes(b: &LoadedBinary) -> Vec<&'static str> {
    b.anomalies.iter().map(|a| a.code).collect()
}

/// File offset of `rva` in section `i` of builder `b`.
fn off(b: &PeBuilder, i: usize, rva: u32) -> u64 {
    let p = b.layout()[i];
    u64::from(p.raw_ptr + (rva - p.va))
}

#[test]
fn minimal_pe32_plus() {
    let b = PeBuilder::new64();
    let bin = ld(&b.build());
    assert_eq!(bin.format, Format::Pe);
    assert_eq!(bin.arch, fg_core::ArchId::X86_64);
    assert_eq!(bin.bitness, fg_core::Bitness::Bits64);
    assert_eq!(bin.kind, BinaryKind::PieExecutable);
    let entry = bin.entry.as_ref().unwrap();
    assert_eq!(entry.value, Va(BASE + 0x1000));
    assert_eq!(
        entry.span,
        Span::new(0x98 + 16, 4),
        "AddressOfEntryPoint field"
    );
    assert_eq!(bin.segments.len(), 2);
    let h = &bin.segments[0];
    assert_eq!(
        (h.name.as_str(), h.va, h.mem_size, h.file_size),
        ("headers", Va(BASE), 0x400, 0x400)
    );
    let t = &bin.segments[1];
    assert_eq!(t.name, ".text");
    assert_eq!(
        (t.va, t.mem_size, t.file_offset, t.file_size),
        (Va(BASE + 0x1000), 0x10, FileOffset(0x400), 0x10)
    );
    assert_eq!(t.perms.to_string(), "R-X");
    assert_eq!(t.defined_by, Span::new(0x188, 40), "section header");
    assert_eq!(
        bin.file_offset_of(Va(BASE + 0x1005)),
        Some(FileOffset(0x405))
    );
    assert_eq!(
        bin.file_offset_of(Va(BASE + 0x0010)),
        Some(FileOffset(0x10)),
        "headers are mapped"
    );
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert_eq!(bin.seeds.len(), 1);
    assert_eq!(bin.seeds[0].kind, SeedKind::Entry);
    let pe = bin.pe().unwrap();
    assert_eq!(pe.optional.image_base.value, BASE);
    assert_eq!(pe.optional.image_base.span, Span::new(0xb0, 8));
    assert_eq!(pe.file_header.machine.span, Span::new(0x84, 2));
    assert!(bin.is_stripped());
}

#[test]
fn minimal_pe32() {
    let b = PeBuilder::new32();
    let bin = ld(&b.build());
    assert_eq!(bin.arch, fg_core::ArchId::X86);
    assert_eq!(bin.bitness, fg_core::Bitness::Bits32);
    let pe = bin.pe().unwrap();
    assert_eq!(pe.optional.base_of_data.as_ref().unwrap().value, 0x2000);
    assert_eq!(pe.optional.image_base.value, 0x40_0000);
    assert_eq!(pe.optional.image_base.span, Span::new(0x98 + 28, 4));
    assert_eq!(bin.entry.as_ref().unwrap().value, Va(0x40_1000));
    assert_eq!(bin.segments[1].defined_by, Span::new(0x98 + 224, 40));
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert!(
        bin.mitigations.seh.is_some(),
        "32-bit x86 gets a SafeSEH verdict"
    );
}

#[test]
fn dll_without_entry() {
    let mut b = PeBuilder::new64();
    b.characteristics |= 0x2000;
    b.entry = 0;
    let bin = ld(&b.build());
    assert_eq!(bin.kind, BinaryKind::SharedObject);
    assert!(bin.entry.is_none());
    assert!(bin.seeds.is_empty());
}

#[test]
fn imports_by_name_and_ordinal() {
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let (blob, lay) = import_blob(
        base,
        true,
        &[
            (
                "KERNEL32.dll",
                vec![Imp::Name("ExitProcess", 0x167), Imp::Ordinal(23)],
            ),
            ("USER32.dll", vec![Imp::Name("MessageBoxA", 2)]),
        ],
    );
    let s = b.section(Sec::new(".rdata", RDATA, blob));
    b.dir(1, lay.dir_rva, lay.dir_size)
        .dir(12, lay.iat_range.0, lay.iat_range.1);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    assert_eq!(pe.imports.len(), 2);
    let k = &pe.imports[0];
    assert_eq!(k.name.value, "KERNEL32.dll");
    assert_eq!(k.descriptor, Span::new(off(&b, s, base), 20));
    let exit = &k.entries[0];
    assert_eq!(exit.name.as_ref().unwrap().value, "ExitProcess");
    assert_eq!(exit.hint.as_ref().unwrap().value, 0x167);
    assert_eq!(exit.iat_va, Va(BASE + u64::from(lay.iats[0])));
    assert_eq!(exit.thunk.span, Span::new(off(&b, s, lay.ilts[0]), 8));
    assert_eq!(k.entries[1].ordinal, Some(23));
    // Neutral model.
    let names: Vec<String> = bin.imports().map(|s| s.display_name()).collect();
    assert_eq!(
        names,
        [
            "KERNEL32.dll!ExitProcess",
            "KERNEL32.dll!#23",
            "USER32.dll!MessageBoxA"
        ]
    );
    let libs: Vec<&str> = bin.libraries.iter().map(|l| l.value.as_str()).collect();
    assert_eq!(libs, ["KERNEL32.dll", "USER32.dll"]);
    // `call [rip+X]` resolution through the IAT slot.
    let slot = bin
        .slot_at(Va(BASE + u64::from(lay.iats[1])))
        .expect("IAT slot");
    assert_eq!(slot.kind, RelocKind::GotEntry);
    assert_eq!(slot.symbol_name.as_deref(), Some("USER32.dll!MessageBoxA"));
    // In an unbound image the IAT starts as a copy of the lookup table.
    assert_eq!(
        slot.stored_value.as_ref().unwrap().value,
        pe.imports[1].entries[0].thunk.value
    );
    assert_eq!(
        bin.mitigations.relro.verdict,
        Verdict::Enabled,
        "IAT in a read-only section"
    );
}

#[test]
fn delay_imports_are_lazy_slots() {
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0xc3; 0x40];
    let rdata = b.next_va();
    let data_va = rdata + 0x1000;
    // .rdata: descriptor, name table, hint/name, DLL name. .data: handle + IAT.
    let mut w = W::default();
    let int = rdata + 64;
    let hn = int + 16;
    let dll = hn + 16;
    w.u32(1)
        .u32(dll)
        .u32(data_va)
        .u32(data_va + 8)
        .u32(int)
        .u32(0)
        .u32(0)
        .u32(0);
    w.bytes(&[0; 32]);
    w.u64(u64::from(hn)).u64(0);
    w.u16(7).cstr("MessageBoxA").align(16);
    w.cstr("USER32.dll");
    b.section(Sec::new(".rdata", RDATA, w.0));
    let mut d = W::default();
    d.u64(0).u64(BASE + 0x1020).u64(0);
    b.section(Sec::new(".data", DATA, d.0));
    b.dir(13, rdata, 64);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    let dl = &pe.delay_imports[0];
    assert_eq!(dl.name.value, "USER32.dll");
    assert_eq!(dl.delay.as_ref().unwrap().module_handle.value, data_va);
    let slot = bin
        .slot_at(Va(BASE + u64::from(data_va) + 8))
        .expect("delay slot");
    assert_eq!(slot.kind, RelocKind::PltSlot);
    assert_eq!(slot.symbol_name.as_deref(), Some("USER32.dll!MessageBoxA"));
    assert_eq!(
        slot.stored_value.as_ref().unwrap().value,
        BASE + 0x1020,
        "the resolving stub"
    );
    assert!(
        bin.libraries.is_empty(),
        "delay-loaded DLLs are not loaded at startup"
    );
    assert_eq!(bin.imports().count(), 1);
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Partial);
}

#[test]
fn exports_with_ordinals_and_forwarders() {
    let mut b = PeBuilder::new64();
    b.characteristics |= 0x2000;
    b.sections[0].data = vec![0xc3; 0x20];
    let base = b.next_va();
    let (blob, size) = export_blob(
        base,
        "test.dll",
        5,
        &[
            Ok(0x1000),
            Ok(0),
            Ok(0x1008),
            Ok(base + 0x1000),
            Err("NTDLL.RtlAllocateHeap"),
        ],
        &[("alpha", 0), ("data_item", 3), ("forwarded", 4)],
    );
    b.section(Sec::new(".rdata", RDATA, blob));
    b.section(Sec::new(".data", DATA, vec![0; 8]));
    b.dir(0, base, size);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let x = bin.pe().unwrap().exports.as_ref().unwrap();
    assert_eq!(x.name.as_ref().unwrap().value, "test.dll");
    let ords: Vec<u32> = x.entries.iter().map(|e| e.ordinal).collect();
    assert_eq!(
        ords,
        [5, 7, 8, 9],
        "the unused slot (ordinal 6) is not an export"
    );
    let ex: Vec<(String, Option<u32>, SymbolKind, Option<String>)> = bin
        .exports()
        .map(|s| (s.display_name(), s.ordinal, s.kind, s.forwarder.clone()))
        .collect();
    assert_eq!(
        ex,
        [
            ("alpha".into(), Some(5), SymbolKind::Function, None),
            ("#7".into(), Some(7), SymbolKind::Function, None),
            ("data_item".into(), Some(8), SymbolKind::Object, None),
            (
                "forwarded".into(),
                Some(9),
                SymbolKind::NoType,
                Some("NTDLL.RtlAllocateHeap".into())
            ),
        ]
    );
}

#[test]
fn base_relocations() {
    let mut b = PeBuilder::new64();
    let data_va = b.next_va();
    let mut d = W::default();
    d.u64(BASE + 0x1000)
        .u32(0x4000_1000)
        .u32(0)
        .u32(0xabcd_0000);
    let ds = b.section(Sec::new(".data", DATA, d.0));
    let reloc_va = b.next_va();
    // DIR64, HIGHLOW, padding, HIGHADJ (+ its parameter slot).
    let blk = reloc_block(data_va, &[0xa000, 0x3008, 0x0000, 0x400c, 0x1234]);
    let len = blk.len() as u32;
    b.section(Sec::new(".reloc", 0x4200_0040, blk));
    b.dir(5, reloc_va, len);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let r: Vec<_> = bin
        .relocations
        .iter()
        .filter(|r| r.table == "base relocations")
        .collect();
    assert_eq!(r.len(), 3, "padding skipped, HIGHADJ parameter consumed");
    assert_eq!(r[0].type_name, Some("IMAGE_REL_BASED_DIR64"));
    assert_eq!(r[0].kind, RelocKind::Relative);
    assert_eq!(r[0].va, Some(Va(BASE + u64::from(data_va))));
    let s0 = r[0].stored_value.as_ref().unwrap();
    assert_eq!(
        (s0.value, s0.span),
        (BASE + 0x1000, Span::new(off(&b, ds, data_va), 8))
    );
    assert_eq!(r[1].type_name, Some("IMAGE_REL_BASED_HIGHLOW"));
    assert_eq!(r[1].stored_value.as_ref().unwrap().value, 0x4000_1000);
    assert_eq!(r[2].type_name, Some("IMAGE_REL_BASED_HIGHADJ"));
    assert_eq!(r[2].kind, RelocKind::Other);
    assert_eq!(bin.pe().unwrap().base_reloc_blocks[0].entries, 5);
    assert_eq!(bin.mitigations.pie.verdict, Verdict::Enabled);
}

#[test]
fn tls_callbacks_are_seeds() {
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0xc3; 0x20];
    let base = b.next_va();
    let mut w = W::default();
    let cbs = base + 0x40;
    w.u64(BASE + u64::from(base) + 0x60)
        .u64(BASE + u64::from(base) + 0x68)
        .u64(BASE + 0x3000)
        .u64(BASE + u64::from(cbs))
        .u32(0)
        .u32(0);
    w.pad_to(0x40);
    w.u64(BASE + 0x1000).u64(BASE + 0x1010).u64(0);
    w.pad_to(0x70);
    let s = b.section(Sec::new(".rdata", RDATA, w.0));
    b.dir(9, base, 40);
    let bin = ld(&b.build());
    assert_eq!(codes(&bin), ["pe.tls.callbacks"]);
    let t = bin.pe().unwrap().tls.as_ref().unwrap();
    assert_eq!(t.callbacks.len(), 2);
    assert_eq!(t.span, Span::new(off(&b, s, base), 40));
    let tls: Vec<(Va, Span)> = bin
        .seeds
        .iter()
        .filter(|s| s.kind == SeedKind::TlsCallback)
        .map(|s| (s.va, s.defined_by))
        .collect();
    assert_eq!(
        tls,
        [
            (Va(BASE + 0x1000), Span::new(off(&b, s, cbs), 8)),
            (Va(BASE + 0x1010), Span::new(off(&b, s, cbs + 8), 8))
        ]
    );
}

/// A 64-bit load configuration of `size` bytes with selected fields set.
fn load_config64(size: u32, fields: &[(usize, u64, usize)]) -> Vec<u8> {
    let mut w = W::default();
    w.u32(size);
    w.pad_to(size as usize);
    for &(at, v, width) in fields {
        match width {
            2 => w.0[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes()),
            4 => w.put_u32(at, v as u32),
            _ => w.put_u64(at, v),
        }
    }
    w.0
}

#[test]
fn load_config_cookie_cfg_and_search_flags() {
    let mut b = PeBuilder::new64();
    b.dll_characteristics |= 0x4000; // GUARD_CF
    b.sections[0].data = vec![0xc3; 0x20];
    let base = b.next_va();
    let table = base + 0x100;
    let flags: u64 = 0x100 | 0x400 | 0x1000_0000; // instrumented, table present, 1 extra byte per entry
    let mut lc = load_config64(
        0x94,
        &[
            (78, 0x800, 2),
            (88, BASE + 0x2000, 8),
            (128, BASE + u64::from(table), 8),
            (136, 2, 8),
            (144, flags, 4),
        ],
    );
    lc.resize(0x100, 0);
    lc.extend([0x00, 0x10, 0, 0, 0, 0x08, 0x10, 0, 0, 1]);
    let s = b.section(Sec::new(".rdata", RDATA, lc));
    b.section(Sec::new(".data", DATA, vec![0; 16]));
    b.dir(10, base, 0x94);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let l = bin.pe().unwrap().load_config.as_ref().unwrap();
    assert_eq!(l.value("SecurityCookie"), BASE + 0x2000);
    assert_eq!(
        l.get("SecurityCookie").unwrap().span,
        Span::new(off(&b, s, base) + 88, 8)
    );
    assert_eq!(l.value("DependentLoadFlags"), 0x800);
    assert!(
        l.get("CodeIntegrityFlags").is_none(),
        "beyond the structure's Size"
    );
    let cfg: Vec<(u32, Option<u8>, u64)> = l
        .guard_cf_functions
        .iter()
        .map(|g| (g.rva, g.flags, g.span.len))
        .collect();
    assert_eq!(cfg, [(0x1000, Some(0), 5), (0x1008, Some(1), 5)]);
    let seeds: Vec<Va> = bin
        .seeds
        .iter()
        .filter(|s| s.kind == SeedKind::CfgTarget)
        .map(|s| s.va)
        .collect();
    assert_eq!(seeds, [Va(BASE + 0x1000), Va(BASE + 0x1008)]);
    let m = &bin.mitigations;
    assert_eq!(m.canary.verdict, Verdict::Enabled);
    assert_eq!(
        m.canary.evidence[0].span,
        Some(l.get("SecurityCookie").unwrap().span)
    );
    assert_eq!(
        m.cfi.verdict,
        Verdict::Partial,
        "CFG without CET shadow stack"
    );
    assert_eq!(
        m.library_paths.verdict,
        Verdict::NotApplicable,
        "no imports"
    );
}

#[test]
fn safeseh_on_x86() {
    let mut b = PeBuilder::new32();
    b.sections[0].data = vec![0xc3; 0x10];
    let base = b.next_va();
    let mut w = W::default();
    w.u32(0x48);
    w.pad_to(0x48);
    w.put_u32(64, 0x40_0000 + base + 0x50);
    w.put_u32(68, 2);
    w.pad_to(0x50);
    w.u32(0x1000).u32(0x1004);
    b.section(Sec::new(".rdata", RDATA, w.0));
    b.dir(10, base, 0x48);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let seh = bin.mitigations.seh.as_ref().unwrap();
    assert_eq!(seh.verdict, Verdict::Enabled);
    let h: Vec<Va> = bin
        .seeds
        .iter()
        .filter(|s| s.kind == SeedKind::SehHandler)
        .map(|s| s.va)
        .collect();
    assert_eq!(h, [Va(0x40_1000), Va(0x40_1004)]);

    let mut b = PeBuilder::new32();
    b.dll_characteristics |= 0x400; // NO_SEH
    assert_eq!(
        ld(&b.build()).mitigations.seh.unwrap().verdict,
        Verdict::Enabled
    );
    let b = PeBuilder::new32();
    assert_eq!(
        ld(&b.build()).mitigations.seh.unwrap().verdict,
        Verdict::Disabled
    );
    assert_eq!(
        ld(&PeBuilder::new64().build())
            .mitigations
            .seh
            .unwrap()
            .verdict,
        Verdict::NotApplicable
    );
}

#[test]
fn x64_exception_table_and_unwind_codes() {
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0xc3; 0x40];
    let rd = b.next_va();
    let mut u = W::default();
    // unw1 @0: v1, EHANDLER, prolog 0x0c, 6 slots, frame RBP at +32.
    u.u8(0x09).u8(0x0c).u8(6).u8(0x25);
    u.u8(0x0c).u8(0x03); // SET_FPREG
    u.u8(0x08).u8(0x01).u16(0x10); // ALLOC_LARGE info 0: 0x10 * 8
    u.u8(0x04).u8(0x34).u16(4); // SAVE_NONVOL RBX at 4 * 8
    u.u8(0x02).u8(0x50); // PUSH_NONVOL RBP
    u.u32(0x1008); // handler
    // unw2 @0x18: chained to entry 1.
    u.pad_to(0x18);
    u.u8(0x21).u8(0).u8(0).u8(0).u32(0x1000).u32(0x1010).u32(rd);
    // unw3 @0x28: v2 with epilogues.
    u.pad_to(0x28);
    u.u8(0x02).u8(4).u8(5).u8(0);
    u.u8(0x01).u8(0x16); // EPILOG (first: length 1, flags 1)
    u.u8(0x02).u8(0x06); // EPILOG offset 2
    u.u8(0x04).u8(0x42); // ALLOC_SMALL 4*8+8
    u.u8(0x04).u8(0x68).u16(2); // SAVE_XMM128 XMM6 at 2*16
    u.u16(0);
    // unw4 @0x3c: ALLOC_LARGE info 1 and PUSH_MACHFRAME.
    u.pad_to(0x3c);
    u.u8(0x01).u8(8).u8(4).u8(0);
    u.u8(0x08).u8(0x11).u16(0).u16(1); // ALLOC_LARGE 0x10000
    u.u8(0x01).u8(0x1a); // PUSH_MACHFRAME with error code
    let s = b.section(Sec::new(".rdata", RDATA, u.0));
    let pd = b.next_va();
    let mut p = W::default();
    p.u32(0x1000).u32(0x1010).u32(rd);
    p.u32(0x1010).u32(0x1020).u32(rd + 0x18);
    p.u32(0x1020).u32(0x1030).u32(rd + 0x28);
    p.u32(0x1030).u32(0x1040).u32(rd + 0x3c);
    let len = p.len();
    b.section(Sec::new(".pdata", RDATA, p.0));
    b.dir(3, pd, len);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    let Some(UnwindInfo::X64(x)) = &pe.exception[0].info else {
        panic!()
    };
    assert_eq!(
        (
            x.version,
            x.prolog_size.value,
            x.frame_register,
            x.frame_offset
        ),
        (1, 0x0c, 5, 2)
    );
    assert_eq!(x.handler.as_ref().unwrap().value, 0x1008);
    assert_eq!(x.span, Span::new(off(&b, s, rd), 20));
    let ops: Vec<(&str, Option<u8>, Option<u32>)> = x
        .codes
        .iter()
        .map(|c| (c.op, c.register, c.value))
        .collect();
    assert_eq!(
        ops,
        [
            ("SET_FPREG", Some(5), Some(32)),
            ("ALLOC_LARGE", None, Some(0x80)),
            ("SAVE_NONVOL", Some(3), Some(0x20)),
            ("PUSH_NONVOL", Some(5), None)
        ]
    );
    let Some(UnwindInfo::X64(x2)) = &pe.exception[1].info else {
        panic!()
    };
    assert_eq!(x2.chained, Some((0x1000, 0x1010, rd)));
    let Some(UnwindInfo::X64(x3)) = &pe.exception[2].info else {
        panic!()
    };
    let ops: Vec<(&str, Option<u32>)> = x3.codes.iter().map(|c| (c.op, c.value)).collect();
    assert_eq!(
        ops,
        [
            ("EPILOG", Some(1)),
            ("EPILOG", Some(2)),
            ("ALLOC_SMALL", Some(40)),
            ("SAVE_XMM128", Some(32))
        ]
    );
    let Some(UnwindInfo::X64(x4)) = &pe.exception[3].info else {
        panic!()
    };
    let ops: Vec<(&str, Option<u32>)> = x4.codes.iter().map(|c| (c.op, c.value)).collect();
    assert_eq!(
        ops,
        [("ALLOC_LARGE", Some(0x10000)), ("PUSH_MACHFRAME", Some(1))]
    );
    let seeds: Vec<(SeedKind, Va, Option<Va>)> = bin
        .seeds
        .iter()
        .filter(|s| s.kind != SeedKind::Entry)
        .map(|s| (s.kind, s.va, s.end))
        .collect();
    assert_eq!(
        seeds[0],
        (
            SeedKind::ExceptionTable,
            Va(BASE + 0x1000),
            Some(Va(BASE + 0x1010))
        )
    );
    assert_eq!(
        seeds[1],
        (
            SeedKind::ExceptionFragment,
            Va(BASE + 0x1010),
            Some(Va(BASE + 0x1020))
        )
    );
}

#[test]
fn arm64_packed_and_xdata_unwind() {
    let mut b = PeBuilder::new64();
    b.machine = ARM64;
    b.sections[0].data = vec![0; 0x300];
    let rd = b.next_va();
    let mut x = W::default();
    x.u32(0x20 | (1 << 20) | (1 << 22) | (2 << 27));
    b.section(Sec::new(".rdata", RDATA, x.0));
    let pd = b.next_va();
    let packed = 1 | (0x10 << 2) | (2 << 16) | (3 << 21) | (4 << 23);
    let fragment = 2 | (0x8 << 2);
    let mut p = W::default();
    p.u32(0x1000)
        .u32(packed)
        .u32(0x1100)
        .u32(rd)
        .u32(0x1200)
        .u32(fragment);
    b.section(Sec::new(".pdata", RDATA, p.0));
    b.dir(3, pd, 24);
    let bin = ld(&b.build());
    assert_eq!(bin.arch, fg_core::ArchId::Aarch64);
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    let Some(UnwindInfo::Arm64Packed(p)) = &pe.exception[0].info else {
        panic!()
    };
    assert_eq!(
        (p.function_length, p.reg_i, p.cr, p.frame_size),
        (0x40, 2, 3, 64)
    );
    let Some(UnwindInfo::Arm64Xdata(x)) = &pe.exception[1].info else {
        panic!()
    };
    assert_eq!(
        (
            x.function_length,
            x.exception_data,
            x.epilogue_count,
            x.code_words
        ),
        (0x80, true, 1, 2)
    );
    let s: Vec<(SeedKind, Va, Option<Va>)> = bin
        .seeds
        .iter()
        .skip(1)
        .map(|s| (s.kind, s.va, s.end))
        .collect();
    assert_eq!(
        s,
        [
            (
                SeedKind::ExceptionTable,
                Va(BASE + 0x1000),
                Some(Va(BASE + 0x1040))
            ),
            (
                SeedKind::ExceptionTable,
                Va(BASE + 0x1100),
                Some(Va(BASE + 0x1180))
            ),
            (
                SeedKind::ExceptionFragment,
                Va(BASE + 0x1200),
                Some(Va(BASE + 0x1220))
            ),
        ]
    );
    assert_eq!(bin.mitigations.cfi.verdict, Verdict::Disabled);
}

#[test]
fn debug_directory_codeview_cet_and_gs_counts() {
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let raw = b.layout().last().unwrap().raw_ptr + b.layout().last().unwrap().raw_size;
    // .rdata: three entries, then their data.
    let data = base + 3 * 28;
    let mut w = W::default();
    let cv_len = 4 + 16 + 4 + 9;
    let entry = |w: &mut W, ty: u32, size: u32, rva: u32| {
        w.u32(0)
            .u32(0x5f00_0000)
            .u16(0)
            .u16(0)
            .u32(ty)
            .u32(size)
            .u32(rva)
            .u32(raw + (rva - base));
    };
    entry(&mut w, 2, cv_len, data);
    entry(&mut w, 20, 4, data + 36);
    entry(&mut w, 12, 20, data + 40);
    w.bytes(b"RSDS");
    w.bytes(&(0u8..16).collect::<Vec<_>>());
    w.u32(3).cstr("c:\\x.pdb");
    w.pad_to((data + 36 - base) as usize);
    w.u32(1); // CET_COMPAT
    w.u32(0).u32(5).u32(4).u32(0).u32(0); // VC feature: 4 of 5 objects with /GS
    b.section(Sec::new(".rdata", RDATA, w.0));
    b.dir(6, base, 3 * 28);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    let DebugContent::CodeView {
        guid,
        age,
        path,
        symbol_server_key,
    } = &pe.debug[0].content
    else {
        panic!("{:?}", pe.debug[0].content)
    };
    let cv = u64::from(raw + (data - base));
    assert_eq!(guid.value, "{03020100-0504-0706-0809-0A0B0C0D0E0F}");
    assert_eq!(guid.span, Span::new(cv + 4, 16));
    assert_eq!((age.value, age.span), (3, Span::new(cv + 20, 4)));
    assert_eq!(
        (path.value.as_str(), path.span),
        ("c:\\x.pdb", Span::new(cv + 24, 8))
    );
    assert_eq!(symbol_server_key, "030201000504070608090A0B0C0D0E0F3");
    let id = bin.build_id.as_ref().unwrap();
    assert_eq!(
        (id.value.as_str(), id.span),
        (symbol_server_key.as_str(), Span::new(cv + 4, 20))
    );
    assert_eq!(pe.ex_dll_characteristics().unwrap().value, 1);
    let m = &bin.mitigations;
    assert_eq!(m.cfi.verdict, Verdict::Partial, "shadow stack only");
    assert_eq!(m.canary.verdict, Verdict::Enabled, "VC feature /GS count");
    assert!(m.canary.evidence.iter().any(|e| e.text.contains("4 of 5")));
}

#[test]
fn resources_tree() {
    let mut b = PeBuilder::new64();
    let rva = b.next_va();
    let mut w = W::default();
    let dir = |w: &mut W, named: u16, ids: u16| {
        w.u32(0).u32(0).u16(0).u16(0).u16(named).u16(ids);
    };
    dir(&mut w, 1, 1);
    w.u32(0x8000_0000 | 160).u32(0x8000_0000 | 32);
    w.u32(10).u32(0x8000_0000 | 56);
    dir(&mut w, 0, 1);
    w.u32(1).u32(0x8000_0000 | 80);
    dir(&mut w, 0, 1);
    w.u32(2).u32(0x8000_0000 | 104);
    dir(&mut w, 0, 1);
    w.u32(1033).u32(128);
    dir(&mut w, 0, 1);
    w.u32(1033).u32(144);
    w.u32(rva + 176).u32(4).u32(1252).u32(0);
    w.u32(rva + 180).u32(4).u32(0).u32(0);
    w.u16(6);
    for c in "MYTYPE".encode_utf16() {
        w.u16(c);
    }
    w.pad_to(176);
    w.bytes(b"abcdwxyz");
    let s = b.section(Sec::new(".rsrc", RDATA, w.0));
    b.dir(2, rva, 184);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let r = &bin.pe().unwrap().resources;
    assert_eq!(r.len(), 2);
    assert_eq!(
        r[0].path,
        [
            ResourceName::Name("MYTYPE".into()),
            ResourceName::Id(1),
            ResourceName::Id(1033)
        ]
    );
    assert_eq!(r[0].type_name(), "\"MYTYPE\"");
    assert_eq!(r[0].code_page.value, 1252);
    assert_eq!(r[0].data, Some(Span::new(off(&b, s, rva + 176), 4)));
    assert_eq!(r[1].type_name(), "RCDATA");
    assert_eq!(r[1].path[1], ResourceName::Id(2));
}

#[test]
fn certificates_and_overlay() {
    let mut b = PeBuilder::new64();
    let end = {
        let p = b.layout()[0];
        p.raw_ptr + p.raw_size
    };
    let mut c = W::default();
    c.u32(24).u16(0x200).u16(2).bytes(&[0xaa; 16]);
    b.trailer = c.0;
    b.dir(4, end, 24);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let pe = bin.pe().unwrap();
    assert_eq!(pe.certificates.len(), 1);
    assert_eq!(pe.certificates[0].cert_type.value, 2);
    assert_eq!(pe.certificates[0].data, Span::new(u64::from(end) + 8, 16));
    assert!(
        pe.overlay.is_none(),
        "a trailing signature is not an overlay"
    );

    let mut b = PeBuilder::new64();
    b.trailer = vec![0x5a; 100];
    let bin = ld(&b.build());
    assert_eq!(codes(&bin), ["pe.overlay"]);
    assert_eq!(bin.pe().unwrap().overlay, Some(Span::new(0x600, 100)));

    let mut b = PeBuilder::new64();
    b.trailer = vec![0; 100];
    assert!(
        ld(&b.build()).anomalies.is_empty(),
        "zero padding is not an overlay"
    );
}

#[test]
fn checksum_round_trip() {
    let b = PeBuilder::new64();
    let file = b.build();
    let sum = ld(&file).pe().unwrap().computed_checksum;
    let mut fixed = file.clone();
    fixed[0xd8..0xdc].copy_from_slice(&sum.to_le_bytes());
    let bin = ld(&fixed);
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert_eq!(
        bin.pe().unwrap().computed_checksum,
        sum,
        "the field itself is excluded"
    );
    fixed[0xd8] ^= 1;
    assert_eq!(codes(&ld(&fixed)), ["pe.optional.checksum"]);
}

#[test]
fn rich_header_decoded_and_verified() {
    let mut b = PeBuilder::new64();
    b.e_lfanew = 0x100;
    let mut file = b.build();
    let entries = [
        ((0x0104u32 << 16) | 30148, 12u32),
        ((0x0102 << 16) | 30148, 1),
    ];
    let key = rich_checksum(&file, 0x80, &entries);
    let mut w = W::default();
    w.u32(0x536e_6144 ^ key).u32(key).u32(key).u32(key);
    for (c, n) in entries {
        w.u32(c ^ key).u32(n ^ key);
    }
    w.u32(0x6863_6952).u32(key);
    file[0x80..0x80 + w.0.len()].copy_from_slice(&w.0);
    let bin = ld(&file);
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let r = bin.pe().unwrap().rich.as_ref().unwrap();
    assert!(r.checksum_valid());
    assert_eq!(r.span, Span::new(0x80, w.0.len() as u64));
    let e: Vec<(u16, u16, u32)> = r
        .entries
        .iter()
        .map(|e| (e.product, e.build, e.count))
        .collect();
    assert_eq!(e, [(0x104, 30148, 12), (0x102, 30148, 1)]);
    file[0x50] ^= 0xff; // edit the DOS stub
    assert_eq!(codes(&ld(&file)), ["pe.rich.checksum"]);
}

#[test]
fn coff_symbols_and_long_section_names() {
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0xc3; 0x20];
    b.section(Sec::new("/4", 0x4200_0040, vec![1; 8]));
    let last = *b.layout().last().unwrap();
    let symtab = last.raw_ptr + last.raw_size;
    b.symtab = (symtab, 4);
    let mut w = W::default();
    w.bytes(b"main\0\0\0\0")
        .u32(0x10)
        .u16(1)
        .u16(0x20)
        .u8(2)
        .u8(0);
    w.u32(0).u32(16).u32(0).u16(0xfffe).u16(0).u8(103).u8(1);
    w.bytes(&[0; 18]); // aux record of the file symbol
    w.bytes(b"tiny\0\0\0\0").u32(4).u16(1).u16(0).u8(3).u8(0);
    w.u32(4 + 12 + 8).cstr(".debug_info").cstr("hello.c");
    b.trailer = w.0;
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert_eq!(bin.pe().unwrap().sections[1].name, ".debug_info");
    let coff: Vec<(u32, &str, Va, SymbolKind)> = bin
        .symbols
        .iter()
        .filter(|s| s.table == SymbolTable::Coff)
        .map(|s| (s.index, s.name.as_str(), s.va, s.kind))
        .collect();
    assert_eq!(
        coff,
        [
            (0, "main", Va(BASE + 0x1010), SymbolKind::Function),
            (1, "hello.c", Va(0), SymbolKind::File),
            (3, "tiny", Va(BASE + 0x1004), SymbolKind::NoType),
        ]
    );
    assert!(!bin.is_stripped());
}

#[test]
fn loader_mapping_rules() {
    // Raw pointer rounded down to 0x200; raw size capped by VirtualSize.
    let mut b = PeBuilder::new64();
    b.sections[0].raw_ptr = Some(0x410);
    b.sections[0].vsize = Some(8);
    let bin = ld(&b.build());
    assert_eq!(codes(&bin), ["pe.section.raw_unaligned"]);
    let t = &bin.segments[1];
    assert_eq!(
        (t.file_offset, t.file_size, t.mem_size),
        (FileOffset(0x400), 8, 8)
    );
    // VirtualSize 0: SizeOfRawData is used.
    let mut b = PeBuilder::new64();
    b.sections[0].vsize = Some(0);
    let bin = ld(&b.build());
    assert_eq!(bin.segments[1].mem_size, 0x200);
    // Low alignment: the file is mapped as is.
    let mut b = PeBuilder::new64();
    b.section_alignment = 0x200;
    b.size_of_headers = 0x200;
    b.entry = 0x200;
    let bin = ld(&b.build());
    assert_eq!(codes(&bin), ["pe.optional.low_alignment"]);
    assert_eq!(
        bin.file_offset_of(Va(BASE + 0x205)),
        Some(FileOffset(0x205))
    );
    assert_eq!(bin.mitigations.separate_code.verdict, Verdict::Partial);
    // Zero-filled section (no file data).
    let mut b = PeBuilder::new64();
    let mut bss = Sec::new(".bss", BSS, Vec::new());
    bss.vsize = Some(0x100);
    b.section(bss);
    let bin = ld(&b.build());
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    assert_eq!(
        (bin.segments[2].file_size, bin.segments[2].mem_size),
        (0, 0x100)
    );
}

#[test]
fn clr_header_is_flagged() {
    let mut b = PeBuilder::new64();
    let rva = b.next_va();
    let mut w = W::default();
    w.u32(72).u16(2).u16(5).u32(0).u32(0).u32(1);
    w.pad_to(72);
    b.section(Sec::new(".text2", RDATA, w.0));
    b.dir(14, rva, 72);
    let bin = ld(&b.build());
    assert_eq!(codes(&bin), ["pe.clr"]);
    let c = bin.pe().unwrap().clr.as_ref().unwrap();
    assert_eq!(
        (
            c.major_runtime_version.value,
            c.minor_runtime_version.value,
            c.flags.value
        ),
        (2, 5, 1)
    );
}

#[test]
fn aslr_dep_and_layout_verdicts() {
    let reloc = |b: &mut PeBuilder| {
        let va = b.next_va();
        let blk = reloc_block(0x1000, &[0xa000]);
        let n = blk.len() as u32;
        b.section(Sec::new(".reloc", RDATA, blk));
        b.dir(5, va, n);
    };
    let v = |b: &PeBuilder| ld(&b.build()).mitigations;

    let mut b = PeBuilder::new64();
    reloc(&mut b);
    assert_eq!(v(&b).pie.verdict, Verdict::Enabled);
    b.dll_characteristics &= !0x20; // no HIGH_ENTROPY_VA
    assert_eq!(v(&b).pie.verdict, Verdict::Partial);
    b.dll_characteristics &= !0x40; // no DYNAMIC_BASE
    let m = v(&b);
    assert_eq!(m.pie.verdict, Verdict::Disabled);
    assert_eq!(ld(&b.build()).kind, BinaryKind::Executable);
    let mut b = PeBuilder::new64();
    reloc(&mut b);
    b.characteristics |= 1; // RELOCS_STRIPPED
    assert_eq!(v(&b).pie.verdict, Verdict::Disabled);
    assert_eq!(
        v(&PeBuilder::new64()).pie.verdict,
        Verdict::Partial,
        "no relocations"
    );

    assert_eq!(
        v(&PeBuilder::new64()).nx.verdict,
        Verdict::Enabled,
        "64-bit: always DEP"
    );
    let mut b = PeBuilder::new32();
    b.dll_characteristics &= !0x100;
    assert_eq!(v(&b).nx.verdict, Verdict::Disabled);
    b.characteristics |= 0x2000;
    assert_eq!(
        v(&b).nx.verdict,
        Verdict::Unknown,
        "a DLL inherits DEP from its host"
    );
    let mut b = PeBuilder::new64();
    b.subsystem = 10;
    assert_eq!(v(&b).nx.verdict, Verdict::Unknown, "UEFI");

    let mut b = PeBuilder::new64();
    b.sections[0].chars = RWX;
    let m = v(&b);
    assert_eq!(m.separate_code.verdict, Verdict::Disabled);
    assert!(
        m.nx.evidence
            .iter()
            .any(|e| e.text.contains("writable and executable"))
    );
    assert_eq!(
        v(&PeBuilder::new64()).separate_code.verdict,
        Verdict::Enabled
    );
    // A data directory inside the code section.
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0; 0x40];
    b.dir(6, 0x1010, 28);
    assert_eq!(v(&b).separate_code.verdict, Verdict::Partial);
}

#[test]
fn iat_in_writable_section_is_not_protected() {
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let (blob, lay) = import_blob(base, true, &[("KERNEL32.dll", vec![Imp::Name("Sleep", 0)])]);
    b.section(Sec::new(".idata", DATA, blob));
    b.dir(1, lay.dir_rva, lay.dir_size);
    let m = ld(&b.build()).mitigations;
    assert_eq!(m.relro.verdict, Verdict::Disabled);
    assert_eq!(
        m.library_paths.verdict,
        Verdict::Partial,
        "default DLL search order"
    );
    assert_eq!(m.canary.verdict, Verdict::Unknown, "no symbols, no cookie");
}

#[test]
fn json_has_pe_metadata() {
    let bin = ld(&PeBuilder::new64().build());
    let v = serde_json::to_value(&bin).unwrap();
    assert_eq!(v["format"], "Pe");
    assert!(v["metadata"]["Pe"]["optional"]["image_base"]["span"]["offset"].is_u64());
    assert_eq!(v["seeds"][0]["kind"], "Entry");
}
