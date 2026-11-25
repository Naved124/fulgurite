// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Malformed and hostile PE files: every anomaly the PE loader can report is
//! triggered here, and the last test checks that none is left untested.

mod common;
use common::pe::*;
use fg_loader::{Limits, LoadError, LoadOptions, load};
use std::collections::BTreeSet;

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    limits: Limits,
    expect: &'static [&'static str],
}

fn case(name: &'static str, b: &PeBuilder, expect: &'static [&'static str]) -> Case {
    Case {
        name,
        bytes: b.build(),
        limits: Limits::default(),
        expect,
    }
}

fn raw(name: &'static str, bytes: Vec<u8>, expect: &'static [&'static str]) -> Case {
    Case {
        name,
        bytes,
        limits: Limits::default(),
        expect,
    }
}

fn limited(mut c: Case, f: impl FnOnce(&mut Limits)) -> Case {
    f(&mut c.limits);
    c
}

/// A builder with `data` as a read-only section; returns the section's RVA.
fn with_rdata(b: &mut PeBuilder, data: Vec<u8>) -> u32 {
    let va = b.next_va();
    b.section(Sec::new(".rdata", RDATA, data));
    va
}

fn codes_of(c: &Case) -> Vec<&'static str> {
    match load(&c.bytes, &LoadOptions::default().with_limits(c.limits)) {
        Ok(b) => b.anomalies.iter().map(|a| a.code).collect(),
        Err(LoadError::Malformed { anomalies, .. }) => anomalies.iter().map(|a| a.code).collect(),
        Err(e) => panic!("{}: {e}", c.name),
    }
}

fn cases() -> Vec<Case> {
    let mut v = Vec::new();

    // ---- DOS / NT headers
    v.push(raw(
        "short MZ",
        b"MZ\x90\x00".to_vec(),
        &["pe.dos.truncated"],
    ));
    let mut dos_only = PeBuilder::new64().build();
    dos_only[0x80] = b'N';
    dos_only[0x81] = b'E';
    v.push(raw("NE executable", dos_only, &["pe.nt.signature"]));
    let mut b = PeBuilder::new64();
    b.e_lfanew = 0x82;
    v.push(case("unaligned e_lfanew", &b, &["pe.dos.lfanew_unaligned"]));
    let mut cut = PeBuilder::new64().build();
    cut.truncate(0x80 + 4 + 10);
    v.push(raw("file header cut", cut, &["pe.file.truncated"]));
    let mut cut = PeBuilder::new64().build();
    cut.truncate(0x98 + 40);
    v.push(raw("optional header cut", cut, &["pe.optional.truncated"]));
    let mut b = PeBuilder::new64();
    b.magic = Some(0x107);
    v.push(case("ROM image", &b, &["pe.optional.magic"]));

    // ---- file and optional header fields
    let mut b = PeBuilder::new64();
    b.pe32_plus = false;
    b.image_base = 0x40_0000;
    v.push(case("PE32 for AMD64", &b, &["pe.optional.magic_machine"]));
    let mut b = PeBuilder::new64();
    b.characteristics = 0x20;
    v.push(case("not executable", &b, &["pe.file.not_executable"]));
    let mut b = PeBuilder::new64();
    b.opt_size = Some(0xe0);
    v.push(case(
        "short SizeOfOptionalHeader",
        &b,
        &["pe.optional.size_small", "pe.optional.size_of_headers"],
    ));
    let mut b = PeBuilder::new64();
    b.nrva = 6;
    v.push(case("six directories", &b, &["pe.optional.rva_count"]));
    let mut b = PeBuilder::new64();
    b.file_alignment = 0x300;
    b.sections[0].raw_ptr = Some(0x400);
    v.push(case("odd file alignment", &b, &["pe.optional.alignment"]));
    let mut b = PeBuilder::new64();
    b.section_alignment = 0x200;
    b.file_alignment = 0x200;
    b.size_of_headers = 0x200;
    b.entry = 0x200;
    b.sections[0].va = Some(0x400);
    v.push(case(
        "low alignment, RVA != offset",
        &b,
        &[
            "pe.optional.low_alignment",
            "pe.section.low_alignment_mismatch",
        ],
    ));
    let mut b = PeBuilder::new64();
    b.section_alignment = 0x200;
    b.file_alignment = 0x100;
    b.size_of_headers = 0x200;
    b.entry = 0x200;
    v.push(case(
        "low alignment, file != section",
        &b,
        &["pe.optional.alignment"],
    ));
    let mut b = PeBuilder::new64();
    b.image_base = 0x1_4000_1000;
    v.push(case(
        "unaligned image base",
        &b,
        &["pe.optional.image_base"],
    ));
    let mut b = PeBuilder::new64();
    b.size_of_image = Some(0x1000);
    v.push(case(
        "SizeOfImage too small",
        &b,
        &["pe.optional.size_of_image", "pe.section.beyond_image"],
    ));
    let mut b = PeBuilder::new64();
    b.size_of_headers = 0x1200;
    b.sections[0].va = Some(0x1000);
    b.sections[0].raw_ptr = Some(0x1200);
    v.push(case(
        "headers overlap a section",
        &b,
        &["pe.optional.size_of_headers"],
    ));
    let mut b = PeBuilder::new64();
    b.win32_version = 1;
    v.push(case("reserved field", &b, &["pe.optional.reserved"]));
    let mut b = PeBuilder::new64();
    b.checksum = 0x1234;
    v.push(case("wrong checksum", &b, &["pe.optional.checksum"]));
    let mut b = PeBuilder::new64();
    b.machine = 0x1d3;
    b.pe32_plus = false;
    v.push(case("unknown machine", &b, &["pe.machine.unknown"]));
    let mut b = PeBuilder::new64();
    b.characteristics |= 1;
    let rva = with_rdata(&mut b, reloc_block(0x1000, &[0xa000]));
    b.dir(5, rva, 10);
    v.push(case(
        "relocations despite RELOCS_STRIPPED",
        &b,
        &["pe.reloc.stripped_flag"],
    ));

    // ---- sections
    let mut b = PeBuilder::new64();
    b.sections.clear();
    b.entry = 0;
    b.characteristics |= 0x2000;
    v.push(case("no sections", &b, &["pe.section.none"]));
    let mut b = PeBuilder::new64();
    for i in 0..3 {
        b.section(Sec::new(&format!(".s{i}"), RDATA, vec![1]));
    }
    v.push(limited(
        case("too many sections", &b, &["pe.section.limit"]),
        |l| l.max_sections = 2,
    ));
    let mut b = PeBuilder::new64();
    b.sections[0].name = b"/99".to_vec();
    v.push(case(
        "unresolvable long name",
        &b,
        &["pe.section.name_invalid"],
    ));
    let mut b = PeBuilder::new64();
    b.number_of_sections = Some(40);
    b.size_of_headers = 0x200;
    b.sections[0].raw_ptr = Some(0x200);
    let mut bytes = b.build();
    bytes.truncate(0x400);
    v.push(raw(
        "section table past the end",
        bytes,
        &["pe.section.table_truncated"],
    ));
    let mut f = PeBuilder::new64().build();
    f[0x188 + 16..0x188 + 20].copy_from_slice(&0x10_0000u32.to_le_bytes());
    v.push(raw("raw data past the end", f, &["pe.section.raw_outside"]));
    let mut b = PeBuilder::new64();
    b.sections[0].raw_ptr = Some(0x410);
    v.push(case(
        "unaligned raw pointer",
        &b,
        &["pe.section.raw_unaligned"],
    ));
    let mut b = PeBuilder::new64();
    b.sections[0].chars = RWX;
    v.push(case("W+X section", &b, &["pe.section.wx"]));
    let mut b = PeBuilder::new64();
    let mut s = Sec::new(".over", RDATA, vec![1; 4]);
    s.va = Some(0x1000);
    b.section(s);
    v.push(case("overlapping sections", &b, &["pe.section.overlap"]));

    // ---- data directories
    let mut b = PeBuilder::new64();
    b.dir(7, 0x1000, 8);
    v.push(case(
        "architecture directory",
        &b,
        &["pe.dir.reserved_used"],
    ));
    let mut b = PeBuilder::new64();
    b.dir(6, 0x9000, 28);
    v.push(case("directory outside the image", &b, &["pe.dir.outside"]));

    // ---- entry point
    let mut b = PeBuilder::new64();
    b.entry = 0;
    v.push(case("entry 0", &b, &["pe.entry.zero"]));
    let mut b = PeBuilder::new64();
    b.entry = 0x10;
    v.push(case("entry in headers", &b, &["pe.entry.in_headers"]));
    let mut b = PeBuilder::new64();
    b.entry = 0x8000;
    v.push(case("entry unmapped", &b, &["pe.entry.unmapped"]));
    let mut b = PeBuilder::new64();
    b.entry = with_rdata(&mut b, vec![0; 16]);
    v.push(case("entry in data", &b, &["pe.entry.not_executable"]));

    // ---- imports
    let mut b = PeBuilder::new64();
    b.dir(1, 0x7000, 40);
    v.push(case(
        "import directory unmapped",
        &b,
        &["pe.import.truncated", "pe.dir.outside"],
    ));
    let two = |b: &mut PeBuilder, dir: usize| {
        let base = b.next_va();
        let (blob, lay) = import_blob(
            base,
            true,
            &[
                ("A.dll", vec![Imp::Name("f", 0)]),
                ("B.dll", vec![Imp::Name("g", 0), Imp::Name("h", 0)]),
            ],
        );
        b.section(Sec::new(".idata", RDATA, blob));
        b.dir(dir, lay.dir_rva, lay.dir_size);
        lay
    };
    let mut b = PeBuilder::new64();
    two(&mut b, 1);
    v.push(limited(
        case("too many DLLs", &b, &["pe.import.limit"]),
        |l| l.max_libraries = 1,
    ));
    v.push(limited(
        case("too many imports", &b, &["pe.import.limit"]),
        |l| l.max_table_entries = 1,
    ));
    let mut b = PeBuilder::new64();
    let lay = two(&mut b, 1);
    b.dir(1, lay.dir_rva, 20);
    v.push(case("import size short", &b, &["pe.import.size"]));
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let (blob, lay) = import_blob(base, true, &[("EMPTY.dll", vec![])]);
    b.section(Sec::new(".idata", RDATA, blob));
    b.dir(1, lay.dir_rva, lay.dir_size);
    v.push(case("DLL with no imports", &b, &["pe.import.empty"]));
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let mut w = W::default();
    // Descriptor: no lookup table, name and IAT unreadable / pointing outside.
    w.u32(0).u32(0).u32(0).u32(0x9000).u32(base + 40);
    w.bytes(&[0; 20]);
    w.u64(0x9000).u64(0);
    b.section(Sec::new(".idata", RDATA, w.0));
    b.dir(1, base, 40);
    v.push(case(
        "import names unreadable",
        &b,
        &["pe.import.no_lookup_table", "pe.import.name_invalid"],
    ));
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let mut w = W::default();
    w.u32(0x9000).u32(0).u32(0).u32(base + 40).u32(base + 48);
    w.bytes(&[0; 20]);
    w.cstr("X.dll");
    b.section(Sec::new(".idata", RDATA, w.0));
    b.dir(1, base, 40);
    v.push(case(
        "lookup table unmapped",
        &b,
        &["pe.import.thunk_unmapped"],
    ));

    // ---- delay imports
    let delay = |attrs: u32, name: u32, int: u32, n: u32| -> (PeBuilder, u32) {
        let mut b = PeBuilder::new64();
        let base = b.next_va();
        let mut w = W::default();
        for i in 0..n {
            let _ = i;
            w.u32(attrs)
                .u32(name.max(base + 160))
                .u32(0)
                .u32(base + 128)
                .u32(int.max(base + 112))
                .u32(0)
                .u32(0)
                .u32(0);
        }
        w.pad_to(96);
        w.pad_to(112);
        w.u64(u64::from(base + 144)).u64(0);
        w.u64(0).u64(0);
        w.u16(0).cstr("f").align(16);
        w.cstr("D.dll");
        w.pad_to(176);
        b.section(Sec::new(".didat", DATA, w.0));
        b.dir(13, base, n * 32);
        (b, base)
    };
    let (b, _) = delay(1, 0, 0, 2);
    v.push(limited(
        case("too many delay DLLs", &b, &["pe.import.limit"]),
        |l| l.max_libraries = 1,
    ));
    // Two descriptors sharing one lookup table: two imports in all.
    let (b, _) = delay(1, 0, 0, 2);
    v.push(limited(
        case(
            "too many imports in the file",
            &b,
            &["pe.import.total_limit"],
        ),
        |l| l.max_imports = 1,
    ));
    let (b, _) = delay(1, 0, 0, 1);
    v.push(limited(
        case("too many delay imports", &b, &["pe.delay.limit"]),
        |l| l.max_table_entries = 0,
    ));
    let mut b = PeBuilder::new64();
    b.dir(13, 0x7000, 32);
    v.push(case(
        "delay directory unmapped",
        &b,
        &["pe.delay.truncated"],
    ));
    let (b, _) = delay(0, 0x1, 0, 1);
    v.push(case(
        "VA-based delay descriptor",
        &b,
        &["pe.delay.va_based", "pe.delay.name_invalid"],
    ));
    let (b, _) = delay(1, 0, 0x9000, 1);
    v.push(case(
        "delay name table unmapped",
        &b,
        &["pe.delay.thunk_unmapped"],
    ));

    // ---- bound imports (in the headers, as linkers place them)
    let mut b = PeBuilder::new64();
    let mut w = W::default();
    w.u32(0x1234).u16(16).u16(0).u32(0).u32(0).cstr("K.dll");
    b.patches.push((0x300, w.0));
    b.dir(11, 0x300, 32);
    v.push(limited(
        case("bound imports over limit", &b, &["pe.bound.limit"]),
        |l| l.max_libraries = 0,
    ));
    let mut b = PeBuilder::new64();
    b.dir(11, 0x3fc, 8);
    v.push(case("bound import cut off", &b, &["pe.bound.truncated"]));

    // ---- exports
    let mut b = PeBuilder::new64();
    b.dir(0, 0x7000, 40);
    v.push(case(
        "export directory unmapped",
        &b,
        &["pe.export.truncated"],
    ));
    let exports = |b: &mut PeBuilder, funcs: &[Result<u32, &str>], names: &[(&str, u16)]| {
        let base = b.next_va();
        let (blob, size) = export_blob(base, "x.dll", 1, funcs, names);
        b.section(Sec::new(".edata", RDATA, blob));
        b.dir(0, base, size);
        base
    };
    let mut b = PeBuilder::new64();
    exports(&mut b, &[Ok(0x1000), Ok(0x1000)], &[("b", 0), ("a", 1)]);
    v.push(case("unsorted export names", &b, &["pe.export.unsorted"]));
    v.push(limited(
        case("too many exports", &b, &["pe.export.limit"]),
        |l| l.max_table_entries = 1,
    ));
    let mut b = PeBuilder::new64();
    exports(&mut b, &[Ok(0x1000)], &[("a", 5)]);
    v.push(case(
        "export ordinal out of range",
        &b,
        &["pe.export.ordinal_invalid"],
    ));
    let mut b = PeBuilder::new64();
    let base = exports(&mut b, &[Ok(0x1000)], &[("a", 0)]);
    let at = b.layout()[1].raw_ptr as usize + 44; // the name pointer
    b.patches.push((at, 0x9000u32.to_le_bytes().to_vec()));
    let _ = base;
    v.push(case(
        "export name unreadable",
        &b,
        &["pe.export.name_invalid"],
    ));

    // ---- base relocations
    let reloc = |entries: &[u16], size_adj: i32| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let blk = reloc_block(0x1000, entries);
        let n = blk.len() as i32 + size_adj;
        let rva = with_rdata(&mut b, blk);
        b.dir(5, rva, n as u32);
        b
    };
    v.push(case(
        "unknown relocation type",
        &reloc(&[0xf000], 0),
        &["pe.reloc.unknown_type"],
    ));
    v.push(case(
        "relocation outside the image",
        &reloc(&[0xafff, 0xa000 | 0x0ff0], 0),
        &[],
    ));
    let mut b = PeBuilder::new64();
    let rva = with_rdata(&mut b, reloc_block(0x8000, &[0xa000]));
    b.dir(5, rva, 10);
    v.push(case(
        "relocation place unmapped",
        &b,
        &["pe.reloc.place_unmapped"],
    ));
    v.push(case(
        "relocation block past directory",
        &reloc(&[0xa000, 0xa008], -2),
        &["pe.reloc.truncated"],
    ));
    let mut b = PeBuilder::new64();
    let mut blk = reloc_block(0x1000, &[0xa000]);
    blk[4] = 3; // block size 3
    let rva = with_rdata(&mut b, blk);
    b.dir(5, rva, 10);
    v.push(case("bad block size", &b, &["pe.reloc.block_size"]));
    v.push(limited(
        case(
            "too many relocations",
            &reloc(&[0xa000, 0xa008], 0),
            &["pe.reloc.limit"],
        ),
        |l| l.max_relocations = 1,
    ));
    let mut b = PeBuilder::new64();
    b.dir(5, 0x1ffc, 16);
    b.sections[0].data = vec![0; 0x1000];
    v.push(case(
        "relocation block unreadable",
        &b,
        &["pe.reloc.truncated"],
    ));

    // ---- TLS
    let tls = |cbs: &[u64], array_va: u64| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let base = b.next_va();
        let mut w = W::default();
        w.u64(0)
            .u64(0)
            .u64(0x1_4000_0000 + u64::from(base) + 0x10)
            .u64(array_va)
            .u32(0)
            .u32(0);
        w.pad_to(0x40);
        for c in cbs {
            w.u64(*c);
        }
        w.u64(0);
        b.section(Sec::new(".tls", DATA, w.0));
        b.dir(9, base, 40);
        b
    };
    let arr = 0x1_4000_2040;
    v.push(case(
        "TLS callbacks",
        &tls(&[0x1_4000_1000], arr),
        &["pe.tls.callbacks"],
    ));
    v.push(case(
        "TLS callback outside",
        &tls(&[0x1_4009_0000], arr),
        &["pe.tls.callback_unmapped"],
    ));
    v.push(case(
        "TLS callback array outside",
        &tls(&[], 0x1_4009_0000),
        &["pe.tls.callback_unmapped"],
    ));
    v.push(case(
        "TLS callback array below base",
        &tls(&[], 0x1000),
        &["pe.tls.callback_unmapped"],
    ));
    v.push(limited(
        case(
            "too many TLS callbacks",
            &tls(&[0x1_4000_1000, 0x1_4000_1000], arr),
            &["pe.tls.limit"],
        ),
        |l| l.max_table_entries = 1,
    ));
    let mut b = PeBuilder::new64();
    b.dir(9, 0x7000, 40);
    v.push(case("TLS directory unmapped", &b, &["pe.tls.truncated"]));
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0; 0x20];
    b.sections[0].vsize = Some(0x1000);
    b.sections[0].raw_size = Some(0x20);
    b.dir(9, 0x1000 + 0x10, 40);
    v.push(case("TLS directory cut", &b, &["pe.tls.truncated"]));

    // ---- load configuration
    let lc = |size: u32, fields: &[(usize, u64)], dir_size: u32| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let base = b.next_va();
        let mut w = W::default();
        w.u32(size);
        w.pad_to(0x150);
        for &(at, val) in fields {
            w.put_u64(at, val);
        }
        b.section(Sec::new(".rdata", RDATA, w.0));
        b.dir(10, base, dir_size);
        b
    };
    v.push(case(
        "load config size mismatch",
        &lc(0x40, &[], 0x48),
        &["pe.loadcfg.size"],
    ));
    v.push(case(
        "hybrid image",
        &lc(0xd0, &[(200, 0x1_4000_2000)], 0xd0),
        &["pe.chpe"],
    ));
    v.push(case(
        "CFG table below base",
        &lc(0x94, &[(128, 0x10), (136, 1)], 0x94),
        &["pe.loadcfg.table_invalid"],
    ));
    v.push(case(
        "CFG table unreadable",
        &lc(0x94, &[(128, 0x1_4000_9000), (136, 1)], 0x94),
        &["pe.loadcfg.table_invalid"],
    ));
    v.push(limited(
        case(
            "CFG table too long",
            &lc(0x94, &[(128, 0x1_4000_2100), (136, 5)], 0x94),
            &["pe.loadcfg.limit"],
        ),
        |l| l.max_table_entries = 2,
    ));
    let mut b = lc(0x94, &[(128, 0x1_4000_2100), (136, 2)], 0x94);
    let at = b.layout()[1].raw_ptr as usize + 0x100;
    b.patches
        .push((at, vec![0x10, 0x10, 0, 0, 0x00, 0x10, 0, 0]));
    v.push(case("CFG table unsorted", &b, &["pe.cfg.unsorted"]));
    v.push(case(
        "SafeSEH table below base",
        &lc(0x94, &[(96, 0x10), (104, 1)], 0x94),
        &["pe.loadcfg.table_invalid"],
    ));
    v.push(case(
        "SafeSEH table unreadable",
        &lc(0x94, &[(96, 0x1_4000_9000), (104, 1)], 0x94),
        &["pe.loadcfg.table_invalid"],
    ));
    let mut b = PeBuilder::new64();
    b.dir(10, 0x7000, 0x40);
    v.push(case("load config unmapped", &b, &["pe.loadcfg.truncated"]));
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0; 0x20];
    b.sections[0].vsize = Some(0x1000);
    b.sections[0].raw_size = Some(0x20);
    b.sections[0].data[0x10] = 0x94;
    b.dir(10, 0x1010, 0x94);
    v.push(case("load config cut off", &b, &["pe.loadcfg.truncated"]));

    // ---- exception table
    let pdata = |machine: u16, entries: &[u32], size_adj: i32| -> PeBuilder {
        let mut b = PeBuilder::new64();
        b.machine = machine;
        if machine == I386 {
            b.pe32_plus = false;
            b.image_base = 0x40_0000;
        }
        b.sections[0].data = vec![0xc3; 0x40];
        let mut w = W::default();
        for e in entries {
            w.u32(*e);
        }
        let n = w.len() as i32 + size_adj;
        let rva = with_rdata(&mut b, w.0);
        b.dir(3, rva, n as u32);
        b
    };
    v.push(case(
        "exception table on i386",
        &pdata(I386, &[0x1000, 0x1010, 0], 0),
        &["pe.pdata.unsupported"],
    ));
    v.push(case(
        "exception table size",
        &pdata(AMD64, &[0x1000, 0x1010, 0x2000, 0], -2),
        &["pe.pdata.size", "pe.pdata.unwind_invalid"],
    ));
    v.push(case(
        "exception entry backwards",
        &pdata(ARM64, &[0x1010, 0x00ff_ffff], 0),
        &["pe.pdata.unwind_invalid"],
    ));
    v.push(case(
        "exception range",
        &pdata(AMD64, &[0x1010, 0x1000, 0x9000], 0),
        &["pe.pdata.range", "pe.pdata.unwind_invalid"],
    ));
    v.push(case(
        "exception unsorted",
        &pdata(ARM64, &[0x1010, 0x5, 0x1000, 0x5], 0),
        &["pe.pdata.unsorted"],
    ));
    v.push(limited(
        case(
            "exception table too long",
            &pdata(ARM64, &[0x1000, 0x5, 0x1010, 0x5], 0),
            &["pe.pdata.limit"],
        ),
        |l| l.max_table_entries = 1,
    ));
    let mut b = PeBuilder::new64();
    b.sections[0].data = vec![0; 0x20];
    b.sections[0].vsize = Some(0x1000);
    b.sections[0].raw_size = Some(0x20);
    b.dir(3, 0x1018, 24);
    v.push(case("exception table cut", &b, &["pe.pdata.truncated"]));

    // ---- debug directory
    // Entries: time stamp, version, type, size, RVA, file offset.
    let debug = |entries: &[[u32; 6]], size: u32| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let mut w = W::default();
        for e in entries {
            w.u32(0);
            for x in e {
                w.u32(*x);
            }
        }
        w.pad_to(0x80);
        w.bytes(b"XXXXjunk");
        let rva = with_rdata(&mut b, w.0);
        b.dir(6, rva, size);
        b
    };
    v.push(case("debug size", &debug(&[], 30), &["pe.debug.size"]));
    v.push(case(
        "debug data outside",
        &debug(&[[0, 0, 2, 0x100, 0, 0x10_0000]], 28),
        &["pe.debug.data_outside"],
    ));
    v.push(case(
        "unknown CodeView",
        &debug(&[[0, 0, 2, 8, 0, 0x600 + 0x80]], 28),
        &["pe.debug.codeview_unknown"],
    ));
    let mut b = PeBuilder::new64();
    b.trailer = vec![1; 8];
    b.dir(6, 0x3f8, 0x1000);
    b.size_of_headers = 0x400;
    v.push(case(
        "debug entries past the end",
        &b,
        &["pe.debug.truncated"],
    ));

    // ---- resources
    let rsrc = |w: W| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let n = w.len();
        let rva = with_rdata(&mut b, w.0);
        b.dir(2, rva, n);
        b
    };
    let dirhdr = |w: &mut W, ids: u16| {
        w.u32(0).u32(0).u32(0).u16(0).u16(ids);
    };
    let mut w = W::default();
    dirhdr(&mut w, 1);
    w.u32(1).u32(0x8000_0000); // subdirectory = the root itself
    v.push(case("resource loop", &rsrc(w), &["pe.resource.loop"]));
    let mut w = W::default();
    dirhdr(&mut w, 1);
    w.u32(1).u32(0x8000_0018);
    dirhdr(&mut w, 1);
    w.u32(1).u32(0x8000_0030);
    dirhdr(&mut w, 1);
    w.u32(1).u32(0x48);
    w.u32(0).u32(0).u32(0).u32(0);
    v.push(limited(
        case("resource tree too deep", &rsrc(w), &["pe.resource.depth"]),
        |l| l.max_resource_depth = 2,
    ));
    let mut w = W::default();
    dirhdr(&mut w, 2);
    w.u32(1).u32(0x20).u32(2).u32(0x20);
    w.u32(0x2000).u32(4).u32(0).u32(0);
    v.push(limited(
        case("too many resources", &rsrc(w), &["pe.resource.limit"]),
        |l| l.max_resources = 1,
    ));
    let mut w = W::default();
    dirhdr(&mut w, 1);
    w.u32(1).u32(0x18);
    w.u32(0x9000).u32(4).u32(0).u32(0);
    v.push(case(
        "resource data outside",
        &rsrc(w),
        &["pe.resource.data_outside"],
    ));
    let mut w = W::default();
    dirhdr(&mut w, 0x200);
    v.push(case(
        "resource entries cut",
        &rsrc(w),
        &["pe.resource.truncated"],
    ));

    // ---- certificates
    let cert = |len: u32, dir: (u32, u32), extra: &[u8]| -> PeBuilder {
        let mut b = PeBuilder::new64();
        let mut w = W::default();
        w.u32(len).u16(0x200).u16(2).bytes(&[0; 8]).bytes(extra);
        b.trailer = w.0;
        b.dir(4, dir.0, dir.1);
        b
    };
    v.push(case(
        "certificate past the end",
        &cert(16, (0x600, 64), &[]),
        &["pe.cert.outside"],
    ));
    v.push(case(
        "certificate bad length",
        &cert(4, (0x600, 16), &[]),
        &["pe.cert.length"],
    ));
    v.push(case(
        "data after the signature",
        &cert(16, (0x600, 16), &[7; 8]),
        &["pe.cert.not_last", "pe.overlay"],
    ));
    v.push(case(
        "certificate inside a section",
        &cert(16, (0x400, 16), &[]),
        &["pe.cert.in_section"],
    ));

    // ---- CLR
    let mut b = PeBuilder::new64();
    let mut w = W::default();
    w.u32(72).u16(2).u16(5);
    w.pad_to(72);
    let rva = with_rdata(&mut b, w.0);
    b.dir(14, rva, 72);
    v.push(case(".NET assembly", &b, &["pe.clr"]));
    let mut b = PeBuilder::new64();
    b.dir(14, 0x7000, 72);
    v.push(case("CLR header unmapped", &b, &["pe.clr.truncated"]));

    // ---- COFF symbols
    let mut b = PeBuilder::new64();
    b.symtab = (0x10_0000, 1);
    v.push(case(
        "COFF pointer past the end",
        &b,
        &["pe.coff.pointer_invalid"],
    ));
    let mut b = PeBuilder::new64();
    b.symtab = (0x600, 3);
    b.trailer = [vec![b'a'; 17], vec![0], vec![b'b'; 2]].concat();
    v.push(case("COFF symbols cut", &b, &["pe.coff.truncated"]));
    v.push(limited(
        case("too many COFF symbols", &b, &["pe.coff.limit"]),
        |l| l.max_symbols = 1,
    ));

    // ---- Rich header and overlay
    let mut b = PeBuilder::new64();
    b.e_lfanew = 0x100;
    let mut f = b.build();
    let key = 0x1111_2222u32;
    let mut w = W::default();
    w.u32(0x536e_6144 ^ key)
        .u32(key)
        .u32(key)
        .u32(key)
        .u32(1 ^ key)
        .u32(1 ^ key)
        .u32(0x6863_6952)
        .u32(key);
    f[0x80..0xa0].copy_from_slice(&w.0);
    v.push(raw("forged Rich header", f, &["pe.rich.checksum"]));
    let mut b = PeBuilder::new64();
    b.trailer = vec![9; 16];
    v.push(case("overlay", &b, &["pe.overlay"]));
    v
}

#[test]
fn every_case_reports_its_codes() {
    let mut failures = Vec::new();
    for c in cases() {
        let got = codes_of(&c);
        for want in c.expect {
            if !got.contains(want) {
                failures.push(format!("{}: expected {want}, got {got:?}", c.name));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_pe_anomaly_code_is_exercised() {
    let sources = [
        include_str!("../src/pe/mod.rs"),
        include_str!("../src/pe/coff.rs"),
        include_str!("../src/pe/debug.rs"),
        include_str!("../src/pe/exception.rs"),
        include_str!("../src/pe/exports.rs"),
        include_str!("../src/pe/imports.rs"),
        include_str!("../src/pe/loadcfg.rs"),
        include_str!("../src/pe/mitigations.rs"),
        include_str!("../src/pe/reloc.rs"),
        include_str!("../src/pe/resource.rs"),
        include_str!("../src/pe/section.rs"),
    ];
    let mut defined = BTreeSet::new();
    for src in sources {
        for part in src.split("\"pe.").skip(1) {
            let end = part.find('"').unwrap();
            let code = &part[..end];
            if code
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
            {
                defined.insert(format!("pe.{code}"));
            }
        }
    }
    let exercised: BTreeSet<String> = cases()
        .iter()
        .flat_map(|c| c.expect.iter().map(|s| s.to_string()))
        .collect();
    let missing: Vec<&String> = defined.difference(&exercised).collect();
    assert!(
        missing.is_empty(),
        "anomaly codes no test triggers: {missing:?}"
    );
    eprintln!("{} PE anomaly codes, all exercised", defined.len());
}

#[test]
fn hostile_cases_never_panic_under_tight_limits() {
    let mut tight = Limits::default();
    tight.max_sections = 1;
    tight.max_symbols = 1;
    tight.max_relocations = 1;
    tight.max_table_entries = 1;
    tight.max_libraries = 1;
    tight.max_resource_depth = 1;
    tight.max_resources = 1;
    tight.max_name_len = 2;
    for c in cases() {
        let _ = load(&c.bytes, &LoadOptions::default().with_limits(tight));
        for cut in [0x40, 0x90, 0x100, 0x200, 0x3ff, 0x401, 0x600] {
            if cut < c.bytes.len() {
                let _ = load(&c.bytes[..cut], &LoadOptions::default());
            }
        }
    }
}

#[test]
fn descriptors_sharing_a_long_lookup_table_are_bounded_in_all() {
    // Thousands of delay-import descriptors all pointing at one lookup table
    // longer than the file-wide import limit. Each DLL alone is within the
    // per-DLL limit, so without a limit on the total the loader would read
    // descriptors × entries imports (hundreds of millions) and run out of
    // memory.
    const DESCRIPTORS: u32 = 4000;
    const ENTRIES: u32 = 70_000;
    let mut b = PeBuilder::new64();
    let base = b.next_va();
    let dir_size = (DESCRIPTORS + 1) * 32;
    let name = base + dir_size;
    let table = name + 16;
    let mut w = W::default();
    for _ in 0..DESCRIPTORS {
        // RVA-based; name; module handle; IAT; INT; bound; unload; time stamp.
        w.u32(1)
            .u32(name)
            .u32(0)
            .u32(table)
            .u32(table)
            .u32(0)
            .u32(0)
            .u32(0);
    }
    w.pad_to(dir_size as usize);
    w.cstr("D.dll").pad_to((dir_size + 16) as usize);
    for i in 0..ENTRIES {
        w.u64(0x8000_0000_0000_0000 | u64::from(i % 0xffff + 1));
    }
    w.u64(0);
    b.section(Sec::new(".didat", DATA, w.0));
    b.dir(13, base, dir_size);
    let bin = load(&b.build(), &LoadOptions::default()).unwrap();
    let limit = Limits::default().max_imports as usize;
    let pe = bin.pe().unwrap();
    let total: usize = pe.delay_imports.iter().map(|d| d.entries.len()).sum();
    assert_eq!(total, limit);
    assert!(
        bin.anomalies
            .iter()
            .any(|a| a.code == "pe.import.total_limit")
    );
}
