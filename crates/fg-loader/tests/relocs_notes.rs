//! Relocations, notes, library paths and the checks built on them, on synthetic
//! files: correct ones (exact values and provenance) and hostile ones (every
//! anomaly code fires, nothing panics).

mod common;
use common::*;
use fg_core::Va;
use fg_loader::elf::{NoteContent, RelocFormat};
use fg_loader::{Limits, LoadOptions, LoadedBinary, RelocKind, Verdict, load};

const BASE: u64 = 0x40_0000;
const PT_NOTE: u32 = 4;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_RPATH: i64 = 15;
const DT_PLTREL: i64 = 20;
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_RUNPATH: i64 = 29;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;

const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;

/// Dynamic string table: `(bytes, offset of each name)`.
const NAMES: &[&str] = &[
    "printf",
    "puts",
    "libc.so.6",
    "$ORIGIN/lib",
    "lib",
    "/opt/x",
    "/a::/b",
];

fn dynstr() -> (Vec<u8>, Vec<u64>) {
    let mut bytes = vec![0u8];
    let mut offs = Vec::new();
    for n in NAMES {
        offs.push(bytes.len() as u64);
        bytes.extend_from_slice(n.as_bytes());
        bytes.push(0);
    }
    (bytes, offs)
}

fn name(n: &str) -> u64 {
    let (_, offs) = dynstr();
    offs[NAMES.iter().position(|x| *x == n).unwrap()]
}

/// A dynamically linked non-PIE executable without section headers.
///
/// File layout (LOAD #0 R-X maps file 0x0.. at BASE, LOAD #1 RW- maps file
/// 0x1000.. at BASE + 0x1000):
/// 0x200 .dynsym (null, printf, puts), 0x280 SysV hash, 0x300 .dynstr,
/// 0x400 RELA tables, 0x500 RELR, 0x600 notes, 0x1000 data and GOT, 0x1800 dynamic.
struct Image {
    e: ElfBuilder,
    dynamic: Vec<(i64, u64)>,
}

fn image() -> Image {
    let mut e = ElfBuilder {
        phdrs: vec![
            Phdr::new(PT_LOAD, PF_R | PF_X)
                .file(0, 0x1000)
                .mem(BASE, 0x1000)
                .align(0x1000),
            Phdr::new(PT_LOAD, PF_R | PF_W)
                .file(0x1000, 0x1000)
                .mem(BASE + 0x1000, 0x1000)
                .align(0x1000),
            Phdr::new(PT_GNU_STACK, PF_R | PF_W).align(0x10),
        ],
        entry: BASE + 0x100,
        min_len: 0x2000,
        ..ElfBuilder::default()
    };
    let func = 0x12; // GLOBAL FUNC
    let syms = e.symbols64(&[
        (name("printf") as u32, func, 0, 0, 0),
        (name("puts") as u32, func, 0, 0, 0),
    ]);
    let (strtab, _) = dynstr();
    let hash: Vec<u8> = [1u32, 3, 0, 0, 0, 0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let strsz = strtab.len() as u64;
    e.blobs.push((0x200, syms));
    e.blobs.push((0x280, hash));
    e.blobs.push((0x300, strtab));
    Image {
        e,
        dynamic: vec![
            (DT_NEEDED, name("libc.so.6")),
            (DT_STRTAB, BASE + 0x300),
            (DT_STRSZ, strsz),
            (DT_SYMTAB, BASE + 0x200),
            (DT_SYMENT, 24),
            (DT_HASH, BASE + 0x280),
        ],
    }
}

impl Image {
    fn dynamic(mut self, entries: &[(i64, u64)]) -> Image {
        self.dynamic.extend_from_slice(entries);
        self
    }
    fn blob(mut self, off: u64, bytes: Vec<u8>) -> Image {
        self.e.blobs.push((off, bytes));
        self
    }
    fn phdr(mut self, p: Phdr) -> Image {
        self.e.phdrs.push(p);
        self
    }
    fn bytes(mut self) -> Vec<u8> {
        let d = self.e.dynamic(&self.dynamic, true);
        self.e.phdrs.push(
            Phdr::new(PT_DYNAMIC, PF_R | PF_W)
                .file(0x1800, d.len() as u64)
                .mem(BASE + 0x1800, d.len() as u64),
        );
        self.e.blobs.push((0x1800, d));
        self.e.build()
    }
    fn load(self) -> LoadedBinary {
        load(&self.bytes(), &LoadOptions::default()).unwrap()
    }
    fn load_with(self, limits: Limits) -> LoadedBinary {
        load(&self.bytes(), &LoadOptions::default().with_limits(limits)).unwrap()
    }
}

fn rela(entries: &[(u64, u32, u32, i64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(off, sym, ty, addend) in entries {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&((u64::from(sym) << 32) | u64::from(ty)).to_le_bytes());
        out.extend_from_slice(&addend.to_le_bytes());
    }
    out
}

fn words(w: &[u64]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn pad(v: &mut Vec<u8>, align: usize) {
    while !v.len().is_multiple_of(align) {
        v.push(0);
    }
}

fn note(owner: &str, ty: u32, desc: &[u8], align: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(owner.len() as u32 + 1).to_le_bytes());
    out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(owner.as_bytes());
    out.push(0);
    pad(&mut out, align);
    out.extend_from_slice(desc);
    pad(&mut out, align);
    out
}

fn property(pr_type: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&pr_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    pad(&mut out, 8);
    out
}

/// An image with one GNU property note (8-byte aligned) at 0x600, with
/// PT_NOTE and PT_GNU_PROPERTY pointing at it.
fn with_properties(mut img: Image, props: &[Vec<u8>]) -> Image {
    let desc: Vec<u8> = props.concat();
    let n = note("GNU", 5, &desc, 8);
    let len = n.len() as u64;
    img = img.blob(0x600, n);
    img.phdr(
        Phdr::new(PT_NOTE, PF_R)
            .file(0x600, len)
            .mem(BASE + 0x600, len)
            .align(8),
    )
    .phdr(
        Phdr::new(PT_GNU_PROPERTY, PF_R)
            .file(0x600, len)
            .mem(BASE + 0x600, len)
            .align(8),
    )
}

#[test]
fn dynamic_relocations_resolve_names_slots_and_stored_values() {
    let got = BASE + 0x1010;
    let table = rela(&[
        (BASE + 0x1000, 0, R_X86_64_RELATIVE, 0x40_0100),
        (BASE + 0x1008, 2, R_X86_64_GLOB_DAT, 0),
        (got, 1, R_X86_64_JUMP_SLOT, 0),
    ]);
    let bin = image()
        .blob(0x400, table[..48].to_vec())
        .blob(0x418 + 24, table[48..].to_vec())
        .blob(0x1010, (BASE + 0x150).to_le_bytes().to_vec())
        .dynamic(&[
            (DT_RELA, BASE + 0x400),
            (DT_RELASZ, 48),
            (DT_RELAENT, 24),
            (DT_JMPREL, BASE + 0x430),
            (DT_PLTRELSZ, 24),
            (DT_PLTREL, DT_RELA as u64),
        ])
        .load();
    assert_eq!(codes(&bin), ["elf.section.none"], "{:?}", bin.anomalies);
    assert_eq!(bin.relocations.len(), 3);
    let r = &bin.relocations;
    assert_eq!(r[0].kind, RelocKind::Relative);
    assert_eq!(r[0].type_name, Some("R_X86_64_RELATIVE"));
    assert_eq!(r[0].addend, Some(0x40_0100));
    assert_eq!(r[0].table, "DT_RELA");
    assert_eq!(r[1].kind, RelocKind::GotEntry);
    assert_eq!(r[1].symbol_name.as_deref(), Some("puts"));
    assert_eq!(r[2].table, "DT_JMPREL");
    assert_eq!(r[2].defined_by.offset.0, 0x430);

    let slot = bin.slot_at(Va(got)).expect("PLT slot found by address");
    assert_eq!(slot.kind, RelocKind::PltSlot);
    assert_eq!(slot.symbol_name.as_deref(), Some("printf"));
    let stored = slot.stored_value.as_ref().unwrap();
    assert_eq!(stored.value, BASE + 0x150, "lazy PLT stub address");
    assert_eq!(
        stored.span.offset.0, 0x1010,
        "read from the slot's file bytes"
    );
    assert!(
        bin.slot_at(Va(BASE + 0x1000)).is_none(),
        "relative is not a slot"
    );

    let names: Vec<&str> = bin.libraries.iter().map(|l| l.value.as_str()).collect();
    assert_eq!(names, ["libc.so.6"]);
    let elf = bin.elf().unwrap();
    assert_eq!(elf.relocations[0].format, RelocFormat::Rela);
    assert!(elf.relocations.iter().all(|t| t.applied_at_load));
    // Partial RELRO evidence counts the lazily bound slot.
    assert_eq!(bin.mitigations.relro.verdict, Verdict::Disabled);
}

#[test]
fn plt_relocations_inside_relasz_are_not_read_twice() {
    // DT_RELASZ covers both tables; DT_JMPREL is its tail (as some linkers emit).
    let table = rela(&[
        (BASE + 0x1000, 0, R_X86_64_RELATIVE, 1),
        (BASE + 0x1008, 0, R_X86_64_RELATIVE, 2),
        (BASE + 0x1010, 1, R_X86_64_JUMP_SLOT, 0),
    ]);
    let bin = image()
        .blob(0x400, table)
        .dynamic(&[
            (DT_RELA, BASE + 0x400),
            (DT_RELASZ, 72),
            (DT_JMPREL, BASE + 0x430),
            (DT_PLTRELSZ, 24),
        ])
        .load();
    assert_eq!(bin.relocations.len(), 3, "the PLT relocation is read once");
    assert!(!codes(&bin).contains(&"elf.reloc.overlap"));

    // Overlapping, but not as a tail: reported.
    let table = rela(&[
        (BASE + 0x1000, 0, R_X86_64_RELATIVE, 1),
        (BASE + 0x1008, 0, R_X86_64_RELATIVE, 2),
        (BASE + 0x1010, 0, R_X86_64_RELATIVE, 3),
    ]);
    let bin = image()
        .blob(0x400, table)
        .dynamic(&[
            (DT_RELA, BASE + 0x400),
            (DT_RELASZ, 72),
            (DT_JMPREL, BASE + 0x418),
            (DT_PLTRELSZ, 24),
        ])
        .load();
    assert!(
        codes(&bin).contains(&"elf.reloc.overlap"),
        "{:?}",
        codes(&bin)
    );
}

#[test]
fn relr_is_decoded() {
    let a = BASE + 0x1000;
    // Address word, then a bitmap for bits 1 and 3 (a+8, a+24), then a bitmap
    // whose only bit (63) is 62 words past the start of its 63-word window.
    let relr = words(&[a, (1 << 1) | (1 << 3) | 1, (1 << 63) | 1]);
    let bin = image()
        .blob(0x500, relr)
        .blob(0x1008, 0x40_0123u64.to_le_bytes().to_vec())
        .dynamic(&[(DT_RELR, BASE + 0x500), (DT_RELRSZ, 24)])
        .load();
    let addrs: Vec<u64> = bin.relocations.iter().map(|r| r.offset).collect();
    let window2 = a + 8 + 63 * 8;
    assert_eq!(addrs, [a, a + 8, a + 24, window2 + 62 * 8]);
    let r1 = &bin.relocations[1];
    assert_eq!(r1.kind, RelocKind::Relative);
    assert_eq!(r1.type_name, Some("R_X86_64_RELATIVE"));
    assert_eq!(r1.defined_by.offset.0, 0x508, "provenance: the bitmap word");
    assert_eq!(
        r1.stored_value.as_ref().unwrap().value,
        0x40_0123,
        "implicit addend"
    );
    let t = &bin.elf().unwrap().relocations[0];
    assert_eq!((t.format, t.relr_words), (RelocFormat::Relr, 3));
    assert!(!codes(&bin).contains(&"elf.relr.no_base"));

    // A bitmap with no preceding address has nothing to be relative to.
    let bin = image()
        .blob(0x500, words(&[0b111]))
        .dynamic(&[(DT_RELR, BASE + 0x500), (DT_RELRSZ, 8)])
        .load();
    assert!(bin.relocations.is_empty());
    assert!(codes(&bin).contains(&"elf.relr.no_base"));
}

#[test]
fn relocations_into_code_are_text_relocations() {
    let table = rela(&[(BASE + 0x100, 0, R_X86_64_RELATIVE, 0)]);
    let undeclared = image()
        .blob(0x400, table.clone())
        .dynamic(&[(DT_RELA, BASE + 0x400), (DT_RELASZ, 24)])
        .load();
    let a = undeclared
        .anomalies
        .iter()
        .find(|a| a.code == "elf.reloc.textrel")
        .unwrap();
    assert!(a.os_behaviour.as_deref().unwrap().contains("faults"));

    let declared = image()
        .blob(0x400, table)
        .dynamic(&[(DT_RELA, BASE + 0x400), (DT_RELASZ, 24), (DT_TEXTREL, 0)])
        .load();
    let a = declared
        .anomalies
        .iter()
        .find(|a| a.code == "elf.reloc.textrel")
        .unwrap();
    assert!(
        a.os_behaviour
            .as_deref()
            .unwrap()
            .contains("DT_TEXTREL is set")
    );
}

#[test]
fn hostile_relocation_tables() {
    let with = |table: Vec<u8>, extra: &[(i64, u64)]| {
        image()
            .blob(0x400, table)
            .dynamic(&[(DT_RELA, BASE + 0x400)])
            .dynamic(extra)
    };
    let one = |off: u64, sym: u32| rela(&[(off, sym, R_X86_64_GLOB_DAT, 0)]);

    let bin = with(one(0x90_0000, 1), &[(DT_RELASZ, 24)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.place_unmapped"));

    let bin = with(one(BASE + 0x1000, 50), &[(DT_RELASZ, 24)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.bad_symbol"));
    assert_eq!(
        bin.relocations[0].symbol_name, None,
        "no name for a bad index"
    );

    let bin = with(one(BASE + 0x1000, 1), &[(DT_RELASZ, 0x10_0000)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.truncated"));

    let bin = with(one(BASE + 0x1000, 1), &[(DT_RELASZ, 30)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.size"));
    assert_eq!(bin.relocations.len(), 1);

    let bin = with(one(BASE + 0x1000, 1), &[(DT_RELASZ, 24), (DT_RELAENT, 16)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.entsize"));
    assert_eq!(bin.relocations.len(), 1, "the real entry size is used");

    let bin = with(rela(&[(BASE + 0x1000, 0, 0x7777, 0)]), &[(DT_RELASZ, 24)]).load();
    assert!(codes(&bin).contains(&"elf.reloc.unknown_type"));
    assert_eq!(bin.relocations[0].type_name, None);

    let bin = image()
        .blob(0x400, one(BASE + 0x1000, 1))
        .dynamic(&[(DT_JMPREL, BASE + 0x400), (DT_PLTRELSZ, 24), (DT_PLTREL, 5)])
        .load();
    assert!(codes(&bin).contains(&"elf.reloc.pltrel_invalid"));

    let bin = with(one(BASE + 0x1000, 1), &[(DT_RELASZ, 24)])
        .dynamic(&[(DT_RELA, BASE + 0x9000)]) // first DT_RELA wins; still fine
        .load();
    assert_eq!(bin.relocations.len(), 1);

    let mut limits = Limits::default();
    limits.max_relocations = 1;
    let table = rela(&[
        (BASE + 0x1000, 0, R_X86_64_RELATIVE, 0),
        (BASE + 0x1008, 0, R_X86_64_RELATIVE, 0),
    ]);
    let bin = with(table, &[(DT_RELASZ, 48)]).load_with(limits);
    assert!(codes(&bin).contains(&"elf.reloc.limit"));
    assert_eq!(bin.relocations.len(), 1);

    // The limit on relocations in all: once two are read, the PLT table is
    // not read at all.
    let mut limits = Limits::default();
    limits.max_total_relocations = 2;
    let bin = image()
        .blob(
            0x400,
            rela(&[
                (BASE + 0x1000, 0, R_X86_64_RELATIVE, 0),
                (BASE + 0x1008, 0, R_X86_64_RELATIVE, 0),
            ]),
        )
        .blob(0x500, one(BASE + 0x1010, 1))
        .dynamic(&[
            (DT_RELA, BASE + 0x400),
            (DT_RELASZ, 48),
            (DT_JMPREL, BASE + 0x500),
            (DT_PLTRELSZ, 24),
            (DT_PLTREL, 7),
        ])
        .load_with(limits);
    assert!(codes(&bin).contains(&"elf.reloc.total_limit"));
    assert!(!codes(&bin).contains(&"elf.reloc.limit"));
    assert_eq!(bin.relocations.len(), 2);

    let bin = image()
        .dynamic(&[(DT_RELA, 0x7000_0000), (DT_RELASZ, 24)])
        .load();
    assert!(codes(&bin).contains(&"elf.dynamic.unmapped"));
    assert!(bin.relocations.is_empty());
}

/// A segment whose file offset is near 2^64 maps a relocation table to the top
/// of the offset range. Counting the symbols relocations use read past 2^64
/// (found while auditing the dynamic-segment bug fuzzing found); the table
/// readers themselves clamp to the file first, and stay checked as well.
#[test]
fn relocation_table_at_the_top_of_the_offset_range() {
    let far = BASE + 0x10_0000;
    for back in [8u64, 16, 24] {
        let bin = image()
            .phdr(
                Phdr::new(PT_LOAD, PF_R)
                    .file(u64::MAX - 0xfff, 0x1000)
                    .mem(far, 0x1000)
                    .align(0x1000),
            )
            .dynamic(&[
                (DT_RELA, far + 0x1000 - back),
                (DT_RELASZ, 24),
                (DT_RELAENT, 24),
            ])
            .load();
        assert!(
            !bin.relocations.iter().any(|r| r.table == "DT_RELA"),
            "{back}"
        );
    }
    // RELR words and the dynamic string table (whose size, DT_STRSZ, can be
    // anything) at the same place: clamped to the file, nothing is read.
    let top = || {
        image().phdr(
            Phdr::new(PT_LOAD, PF_R)
                .file(u64::MAX - 0xfff, 0x1000)
                .mem(far, 0x1000)
                .align(0x1000),
        )
    };
    let bin = top()
        .dynamic(&[(DT_RELR, far + 0xff8), (DT_RELRSZ, 16), (DT_RELRENT, 8)])
        .load();
    assert!(!bin.relocations.iter().any(|r| r.table == "DT_RELR"));
    let mut img = top();
    img.dynamic
        .retain(|(t, _)| *t != DT_STRTAB && *t != DT_STRSZ);
    let bin = img
        // The table starts at the very last offset.
        .dynamic(&[(DT_STRTAB, far + 0xfff), (DT_STRSZ, u64::MAX)])
        .load();
    assert!(bin.libraries.is_empty());
}

#[test]
fn build_id_and_cet_marking() {
    let build_id = note("GNU", 3, &[0xde, 0xad, 0xbe, 0xef], 4);
    let len = build_id.len() as u64;
    let bin = with_properties(
        image(),
        &[
            property(0xc000_0002, &3u32.to_le_bytes()),
            property(0xc000_8002, &1u32.to_le_bytes()),
        ],
    )
    .blob(0x700, build_id)
    .phdr(
        Phdr::new(PT_NOTE, PF_R)
            .file(0x700, len)
            .mem(BASE + 0x700, len)
            .align(4),
    )
    .load();
    assert_eq!(codes(&bin), ["elf.section.none"], "{:?}", bin.anomalies);
    let id = bin.build_id.as_ref().unwrap();
    assert_eq!(id.value, "deadbeef");
    assert_eq!(id.span.offset.0, 0x710, "provenance: the descriptor bytes");

    let elf = bin.elf().unwrap();
    let props = elf.property_note().unwrap().properties();
    let texts: Vec<&str> = props.iter().map(|p| p.text.as_str()).collect();
    assert_eq!(
        texts,
        ["x86 feature: IBT, SHSTK", "x86 ISA needed: x86-64-baseline"]
    );
    let cfi = &bin.mitigations.cfi;
    assert_eq!(cfi.verdict, Verdict::Enabled, "{cfi:?}");
    assert!(cfi.summary.contains("IBT and SHSTK"));
    assert_eq!(cfi.evidence[0].span, props[0].bits.as_ref().map(|b| b.span));
}

#[test]
fn cfi_verdicts() {
    let feature = |bits: u32| property(0xc000_0002, &bits.to_le_bytes());
    let v = |img: Image| img.load().mitigations.cfi.verdict;
    assert_eq!(v(with_properties(image(), &[feature(1)])), Verdict::Partial);
    assert_eq!(
        v(with_properties(image(), &[feature(0)])),
        Verdict::Disabled
    );
    assert_eq!(
        v(with_properties(
            image(),
            &[property(0xc000_8002, &1u32.to_le_bytes())]
        )),
        Verdict::Disabled,
        "a property note without the feature entry is not marked"
    );
    assert_eq!(v(image()), Verdict::Disabled, "no note: not marked");
    let bin = with_properties(image(), &[property(0xc000_0002, &[3, 0, 0, 0, 0, 0, 0, 0])]).load();
    assert_eq!(
        bin.mitigations.cfi.verdict,
        Verdict::Unknown,
        "corrupt length"
    );
    let text = &bin.elf().unwrap().notes[0].properties()[0].text;
    assert_eq!(text, "x86 feature: <corrupt length: 0x8> ");
}

#[test]
fn aarch64_bti_and_pac() {
    let mut img = image();
    img.e.machine = 183;
    let desc = property(0xc000_0000, &3u32.to_le_bytes());
    let n = note("GNU", 5, &desc, 8);
    let len = n.len() as u64;
    let bin = img
        .blob(0x600, n)
        .phdr(
            Phdr::new(PT_NOTE, PF_R)
                .file(0x600, len)
                .mem(BASE + 0x600, len)
                .align(8),
        )
        .load();
    assert_eq!(bin.mitigations.cfi.verdict, Verdict::Enabled);
    assert!(bin.mitigations.cfi.summary.contains("BTI and PAC"));
    assert_eq!(
        bin.elf().unwrap().notes[0].properties()[0].text,
        "AArch64 feature: BTI, PAC"
    );
    assert!(
        codes(&bin).contains(&"elf.property.no_segment"),
        "the kernel needs PT_GNU_PROPERTY to enable BTI"
    );
}

#[test]
fn hostile_notes() {
    let at = |img: Image, bytes: Vec<u8>, align: u64| {
        let len = bytes.len() as u64;
        img.blob(0x600, bytes).phdr(
            Phdr::new(PT_NOTE, PF_R)
                .file(0x600, len)
                .mem(BASE + 0x600, len)
                .align(align),
        )
    };
    // Descriptor size runs past the segment.
    let mut n = note("GNU", 3, &[1, 2, 3, 4], 4);
    n[4] = 0xff;
    let bin = at(image(), n, 4).load();
    assert!(codes(&bin).contains(&"elf.note.truncated"));
    assert!(bin.build_id.is_none());

    let bin = at(image(), note("GNU", 3, &[1; 4], 4), 16).load();
    assert!(codes(&bin).contains(&"elf.note.align"));
    assert_eq!(bin.build_id.unwrap().value, "01010101", "still read with 4");

    // A property claiming more data than the note holds.
    let mut p = property(0xc000_0002, &3u32.to_le_bytes());
    p[4] = 0x40;
    let bin = with_properties(image(), &[p]).load();
    assert!(codes(&bin).contains(&"elf.property.corrupt"));

    // PT_GNU_PROPERTY pointing at a build-ID note.
    let bin = at(image(), note("GNU", 3, &[9; 4], 4), 4)
        .phdr(Phdr::new(PT_GNU_PROPERTY, PF_R).file(0x600, 20).align(8))
        .load();
    assert!(codes(&bin).contains(&"elf.property.segment_mismatch"));

    // Two property notes.
    let one = note("GNU", 5, &property(0xc000_0002, &1u32.to_le_bytes()), 8);
    let bin = at(image(), [one.clone(), one].concat(), 8).load();
    assert!(codes(&bin).contains(&"elf.property.multiple"));

    let mut limits = Limits::default();
    limits.max_notes = 1;
    let two = [note("GNU", 3, &[1; 4], 4), note("GNU", 1, &[0; 16], 4)].concat();
    let bin = at(image(), two, 4).load_with(limits);
    assert!(codes(&bin).contains(&"elf.note.limit"));
    assert_eq!(bin.elf().unwrap().notes.len(), 1);

    let tiny = at(image(), vec![4, 0, 0, 0, 0], 4).load();
    assert!(codes(&tiny).contains(&"elf.note.truncated"));
}

#[test]
fn abi_tag_and_other_owners() {
    let abi = note(
        "GNU",
        1,
        &[0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        4,
    );
    let pkg = note("FDO", 0xcafe_1a7e, b"{\"type\":\"rpm\"}\0", 4);
    let bytes = [abi, pkg].concat();
    let len = bytes.len() as u64;
    let bin = image()
        .blob(0x600, bytes)
        .phdr(Phdr::new(PT_NOTE, PF_R).file(0x600, len).align(4))
        .load();
    let notes = &bin.elf().unwrap().notes;
    assert_eq!(
        notes[0].content,
        NoteContent::AbiTag {
            os: "Linux".into(),
            version: "3.2.0".into()
        }
    );
    assert_eq!(
        notes[1].content,
        NoteContent::Package("{\"type\":\"rpm\"}".into())
    );
}

#[test]
fn library_search_paths() {
    let lp = |entries: &[(i64, u64)]| image().dynamic(entries).load().mitigations.library_paths;
    let none = lp(&[]);
    assert_eq!(none.verdict, Verdict::Enabled);
    let origin = lp(&[(DT_RUNPATH, name("$ORIGIN/lib"))]);
    assert_eq!(origin.verdict, Verdict::Partial);
    assert!(origin.summary.contains("$ORIGIN/lib"));
    assert_eq!(lp(&[(DT_RUNPATH, name("lib"))]).verdict, Verdict::Disabled);
    assert_eq!(
        lp(&[(DT_RPATH, name("/a::/b"))]).verdict,
        Verdict::Disabled,
        "an empty entry means the current directory"
    );
    let abs = lp(&[(DT_RPATH, name("/opt/x"))]);
    assert_eq!(abs.verdict, Verdict::Enabled);
    assert!(
        abs.evidence
            .iter()
            .any(|e| e.text.contains("before LD_LIBRARY_PATH"))
    );
    let both = lp(&[(DT_RPATH, name("/opt/x")), (DT_RUNPATH, name("lib"))]);
    assert!(
        both.evidence
            .iter()
            .any(|e| e.text.contains("ignores RPATH"))
    );

    let bin = image().dynamic(&[(DT_RUNPATH, name("$ORIGIN/lib"))]).load();
    let rp = bin.elf().unwrap().strings.runpath.as_ref().unwrap();
    assert_eq!(rp.value, "$ORIGIN/lib");
    assert_eq!(rp.span.offset.0, 0x300 + name("$ORIGIN/lib"));
}

#[test]
fn dynamic_string_problems() {
    let bin = image().dynamic(&[(DT_NEEDED, 0x9999)]).load();
    assert!(codes(&bin).contains(&"elf.dynamic.string_invalid"));
    assert_eq!(bin.libraries.len(), 1, "the valid one is kept");

    let mut img = image();
    img.dynamic.retain(|(t, _)| *t != DT_STRTAB);
    let bin = img.load();
    assert!(codes(&bin).contains(&"elf.dynamic.no_strtab"));
    assert!(bin.libraries.is_empty());
}

#[test]
fn separate_code_verdicts() {
    // minimal_exec: one R-X LOAD starting at file offset 0 (headers executable).
    let bin = load(&minimal_exec().build(), &LoadOptions::default()).unwrap();
    let m = &bin.mitigations.separate_code;
    assert_eq!(m.verdict, Verdict::Partial);
    assert!(m.evidence[0].text.contains("file offset 0"));

    let mut e = minimal_exec();
    e.phdrs[0].flags = PF_R | PF_W | PF_X;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.separate_code.verdict, Verdict::Disabled);

    let mut e = minimal_exec();
    e.phdrs[0] = Phdr::new(PT_LOAD, PF_R | PF_X)
        .file(0x1000, 0x100)
        .mem(0x40_1000, 0x100)
        .align(0x1000);
    e.entry = 0x40_1000;
    e.min_len = 0x1100;
    let bin = load(&e.build(), &LoadOptions::default()).unwrap();
    assert_eq!(bin.mitigations.separate_code.verdict, Verdict::Enabled);
}

/// A relocatable object: `.text`, `.rela.text`, `.symtab`, `.strtab`.
fn object(rela_link: u32, rela_info: u32) -> ElfBuilder {
    let mut e = ElfBuilder {
        e_type: ET_REL,
        entry: 0,
        ..ElfBuilder::default()
    };
    let syms = e.symbols64(&[(1, 0x12, 1, 0, 8)]); // GLOBAL FUNC "f" in section 1
    let strtab = b"\0f\0".to_vec();
    let text = vec![0xe8, 0, 0, 0, 0, 0xc3, 0, 0];
    let relocs = rela(&[(1, 1, 4, -4)]); // R_X86_64_PLT32 f - 4
    let (t, r, s, st) = (0x100u64, 0x140u64, 0x180u64, 0x200u64);
    e.blobs.push((t, text));
    e.blobs.push((r, relocs));
    e.blobs.push((s, syms.clone()));
    e.blobs.push((st, strtab));
    e.sections = vec![
        Shdr::new(".text", SHT_PROGBITS)
            .at(t, 8)
            .flags(SHF_ALLOC | SHF_EXECINSTR),
        Shdr::new(".rela.text", 4)
            .at(r, 24)
            .link(rela_link, rela_info)
            .flags(0x40)
            .entsize(24),
        Shdr::new(".symtab", SHT_SYMTAB)
            .at(s, syms.len() as u64)
            .link(4, 1)
            .entsize(24),
        Shdr::new(".strtab", SHT_STRTAB).at(st, 3),
    ];
    e
}

#[test]
fn object_file_relocations_use_section_offsets() {
    let bin = load(&object(3, 1).build(), &LoadOptions::default()).unwrap();
    assert!(bin.anomalies.is_empty(), "{:?}", bin.anomalies);
    let r = &bin.relocations[0];
    assert_eq!(r.table, ".rela.text");
    assert_eq!((r.va, r.section, r.offset), (None, Some(1), 1));
    assert_eq!(r.type_name, Some("R_X86_64_PLT32"));
    assert_eq!(r.symbol_name.as_deref(), Some("f"));
    assert_eq!(r.addend, Some(-4));
    assert!(
        r.stored_value.is_none(),
        "RELA objects: bytes at the place are not an addend"
    );
    let t = &bin.elf().unwrap().relocations[0];
    assert!(!t.applied_at_load);
    assert_eq!(t.applies_to, Some(1));

    let bin = load(&object(1, 1).build(), &LoadOptions::default()).unwrap();
    assert!(codes(&bin).contains(&"elf.reloc.symtab_invalid"));
    let bin = load(&object(3, 99).build(), &LoadOptions::default()).unwrap();
    assert!(codes(&bin).contains(&"elf.reloc.target_invalid"));
}

#[test]
fn section_headers_name_dynamic_tables() {
    let table = rela(&[(BASE + 0x1000, 0, R_X86_64_RELATIVE, 7)]);
    let mut img = image()
        .blob(0x400, table.clone())
        .blob(0x480, table)
        .dynamic(&[(DT_RELA, BASE + 0x400), (DT_RELASZ, 24)]);
    img.e.sections = vec![
        Shdr::new(".rela.dyn", 4)
            .at(0x400, 24)
            .addr(BASE + 0x400)
            .flags(SHF_ALLOC)
            .entsize(24),
        Shdr::new(".rela.extra", 4)
            .at(0x480, 24)
            .addr(BASE + 0x480)
            .flags(SHF_ALLOC)
            .entsize(24),
    ];
    let bin = img.load();
    let elf = bin.elf().unwrap();
    assert_eq!(elf.relocations[0].name, ".rela.dyn", "named by its section");
    assert_eq!(elf.relocations[0].section, Some(1));
    assert!(codes(&bin).contains(&"elf.reloc.section_unused"));
    assert!(!elf.relocations[1].applied_at_load);
}

#[test]
fn every_truncation_of_a_file_with_relocations_and_notes_is_safe() {
    let bytes = with_properties(image(), &[property(0xc000_0002, &3u32.to_le_bytes())])
        .blob(0x400, rela(&[(BASE + 0x1010, 1, R_X86_64_JUMP_SLOT, 0)]))
        .blob(0x500, words(&[BASE + 0x1000, 0b1011]))
        .dynamic(&[
            (DT_JMPREL, BASE + 0x400),
            (DT_PLTRELSZ, 24),
            (DT_RELR, BASE + 0x500),
            (DT_RELRSZ, 16),
            (DT_RUNPATH, name("$ORIGIN/lib")),
        ])
        .bytes();
    for len in 0..bytes.len() {
        let _ = load(&bytes[..len], &LoadOptions::default());
    }
    let full = load(&bytes, &LoadOptions::default()).unwrap();
    assert_eq!(full.relocations.len(), 4);
}
