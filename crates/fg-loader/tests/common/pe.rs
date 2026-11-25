// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Test helper: builds small synthetic PE images, correct or deliberately broken.
#![allow(dead_code, missing_docs)]

pub const AMD64: u16 = 0x8664;
pub const I386: u16 = 0x14c;
pub const ARM64: u16 = 0xaa64;
pub const CODE: u32 = 0x6000_0020; // CNT_CODE | EXECUTE | READ
pub const RDATA: u32 = 0x4000_0040; // INITIALIZED_DATA | READ
pub const DATA: u32 = 0xc000_0040; // INITIALIZED_DATA | READ | WRITE
pub const BSS: u32 = 0xc000_0080;
pub const RWX: u32 = 0xe000_0020;

/// Little-endian byte writer.
#[derive(Clone, Debug, Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) -> &mut W {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut W {
        self.0.extend(v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut W {
        self.0.extend(v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut W {
        self.0.extend(v.to_le_bytes());
        self
    }
    /// A pointer-sized value.
    pub fn ptr(&mut self, v: u64, plus: bool) -> &mut W {
        if plus {
            self.u64(v)
        } else {
            self.u32(v as u32)
        }
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut W {
        self.0.extend_from_slice(b);
        self
    }
    pub fn cstr(&mut self, s: &str) -> &mut W {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
    pub fn align(&mut self, n: usize) -> &mut W {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
        self
    }
    pub fn pad_to(&mut self, len: usize) -> &mut W {
        if self.0.len() < len {
            self.0.resize(len, 0);
        }
        self
    }
    pub fn len(&self) -> u32 {
        self.0.len() as u32
    }
    pub fn put_u32(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    pub fn put_u64(&mut self, at: usize, v: u64) {
        self.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct Sec {
    pub name: Vec<u8>,
    pub chars: u32,
    pub data: Vec<u8>,
    /// Overrides (default: computed layout).
    pub va: Option<u32>,
    pub vsize: Option<u32>,
    pub raw_ptr: Option<u32>,
    pub raw_size: Option<u32>,
}

impl Sec {
    pub fn new(name: &str, chars: u32, data: Vec<u8>) -> Sec {
        Sec {
            name: name.as_bytes().to_vec(),
            chars,
            data,
            va: None,
            vsize: None,
            raw_ptr: None,
            raw_size: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeBuilder {
    pub pe32_plus: bool,
    pub magic: Option<u16>,
    pub machine: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub subsystem: u16,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub entry: u32,
    pub e_lfanew: u32,
    pub opt_size: Option<u16>,
    pub nrva: u32,
    pub dirs: [(u32, u32); 16],
    pub sections: Vec<Sec>,
    pub checksum: u32,
    pub size_of_image: Option<u32>,
    pub size_of_headers: u32,
    pub symtab: (u32, u32),
    pub win32_version: u32,
    pub number_of_sections: Option<u16>,
    /// Bytes written at fixed file offsets after everything else.
    pub patches: Vec<(usize, Vec<u8>)>,
    /// Bytes appended after the last section.
    pub trailer: Vec<u8>,
}

/// Where a section ended up.
#[derive(Clone, Copy, Debug)]
pub struct Placed {
    pub va: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
}

fn align(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

impl PeBuilder {
    pub fn new64() -> PeBuilder {
        PeBuilder {
            pe32_plus: true,
            magic: None,
            machine: AMD64,
            characteristics: 0x22,
            dll_characteristics: 0x0160,
            subsystem: 3,
            image_base: 0x1_4000_0000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            entry: 0x1000,
            e_lfanew: 0x80,
            opt_size: None,
            nrva: 16,
            dirs: [(0, 0); 16],
            sections: vec![Sec::new(".text", CODE, vec![0xc3; 0x10])],
            checksum: 0,
            size_of_image: None,
            size_of_headers: 0x400,
            symtab: (0, 0),
            win32_version: 0,
            number_of_sections: None,
            patches: Vec::new(),
            trailer: Vec::new(),
        }
    }

    pub fn new32() -> PeBuilder {
        PeBuilder {
            pe32_plus: false,
            machine: I386,
            characteristics: 0x102,
            dll_characteristics: 0x0140,
            image_base: 0x40_0000,
            ..PeBuilder::new64()
        }
    }

    /// Adds a section and returns its index.
    pub fn section(&mut self, s: Sec) -> usize {
        self.sections.push(s);
        self.sections.len() - 1
    }

    pub fn dir(&mut self, i: usize, rva: u32, size: u32) -> &mut PeBuilder {
        self.dirs[i] = (rva, size);
        self
    }

    pub fn opt_fixed(&self) -> u32 {
        if self.pe32_plus { 112 } else { 96 }
    }

    pub fn opt_offset(&self) -> u32 {
        self.e_lfanew + 24
    }

    pub fn section_table_offset(&self) -> u32 {
        self.opt_offset()
            + u32::from(
                self.opt_size
                    .unwrap_or((self.opt_fixed() + self.nrva.min(16) * 8) as u16),
            )
    }

    /// The RVA the next added section will get (with the default layout).
    pub fn next_va(&self) -> u32 {
        self.layout().last().map_or(self.section_alignment, |p| {
            align(p.va + p.vsize.max(1), self.section_alignment)
        })
    }

    pub fn layout(&self) -> Vec<Placed> {
        let mut out: Vec<Placed> = Vec::new();
        let mut va = align(self.size_of_headers.max(1), self.section_alignment);
        let mut raw = align(self.size_of_headers, self.file_alignment);
        for s in &self.sections {
            let vsize = s.vsize.unwrap_or(s.data.len() as u32);
            let p = Placed {
                va: s.va.unwrap_or(va),
                vsize,
                raw_ptr: s.raw_ptr.unwrap_or(if s.data.is_empty() { 0 } else { raw }),
                raw_size: s
                    .raw_size
                    .unwrap_or(align(s.data.len() as u32, self.file_alignment)),
            };
            va = align(p.va + vsize.max(1), self.section_alignment);
            if p.raw_ptr != 0 {
                raw = raw.max(p.raw_ptr + align(s.data.len() as u32, self.file_alignment));
            }
            out.push(p);
        }
        out
    }

    pub fn build(&self) -> Vec<u8> {
        let plus = self.pe32_plus;
        let layout = self.layout();
        let mut f = W::default();
        // DOS header.
        f.u16(0x5a4d);
        f.pad_to(0x3c);
        f.u32(self.e_lfanew);
        f.pad_to(self.e_lfanew as usize);
        // NT headers.
        f.u32(0x4550);
        f.u16(self.machine)
            .u16(
                self.number_of_sections
                    .unwrap_or(self.sections.len() as u16),
            )
            .u32(0x5f00_0000)
            .u32(self.symtab.0)
            .u32(self.symtab.1)
            .u16(
                self.opt_size
                    .unwrap_or((self.opt_fixed() + self.nrva.min(16) * 8) as u16),
            )
            .u16(self.characteristics);
        let soi = self.size_of_image.unwrap_or_else(|| {
            layout.last().map_or(self.section_alignment, |p| {
                align(p.va + p.vsize.max(1), self.section_alignment)
            })
        });
        let opt = f.len();
        f.u16(self.magic.unwrap_or(if plus { 0x20b } else { 0x10b }))
            .u8(14)
            .u8(0)
            .u32(0x200)
            .u32(0x200)
            .u32(0)
            .u32(self.entry)
            .u32(0x1000);
        if !plus {
            f.u32(0x2000);
        }
        f.ptr(self.image_base, plus)
            .u32(self.section_alignment)
            .u32(self.file_alignment)
            .u16(6)
            .u16(0)
            .u16(0)
            .u16(0)
            .u16(6)
            .u16(0)
            .u32(self.win32_version)
            .u32(soi)
            .u32(self.size_of_headers)
            .u32(self.checksum)
            .u16(self.subsystem)
            .u16(self.dll_characteristics)
            .ptr(0x10_0000, plus)
            .ptr(0x1000, plus)
            .ptr(0x10_0000, plus)
            .ptr(0x1000, plus)
            .u32(0)
            .u32(self.nrva);
        assert_eq!(f.len() - opt, self.opt_fixed());
        for (rva, size) in self.dirs.iter().take(self.nrva.min(16) as usize) {
            f.u32(*rva).u32(*size);
        }
        f.pad_to(self.section_table_offset() as usize);
        for (s, p) in self.sections.iter().zip(&layout) {
            let mut name = s.name.clone();
            name.resize(8, 0);
            f.bytes(&name)
                .u32(p.vsize)
                .u32(p.va)
                .u32(p.raw_size)
                .u32(p.raw_ptr)
                .u32(0)
                .u32(0)
                .u16(0)
                .u16(0)
                .u32(s.chars);
        }
        f.pad_to(self.size_of_headers as usize);
        for (s, p) in self.sections.iter().zip(&layout) {
            if p.raw_ptr == 0 || s.data.is_empty() {
                continue;
            }
            f.pad_to(p.raw_ptr as usize);
            let at = p.raw_ptr as usize;
            let end = at + s.data.len();
            if f.0.len() < end {
                f.0.resize(end, 0);
            }
            f.0[at..end].copy_from_slice(&s.data);
            f.pad_to(at + p.raw_size as usize);
        }
        f.bytes(&self.trailer);
        for (at, bytes) in &self.patches {
            let end = at + bytes.len();
            if f.0.len() < end {
                f.0.resize(end, 0);
            }
            f.0[*at..end].copy_from_slice(bytes);
        }
        f.0
    }
}

/// One import: by name (with hint) or by ordinal.
#[derive(Clone, Copy, Debug)]
pub enum Imp<'a> {
    Name(&'a str, u16),
    Ordinal(u16),
}

/// Where the parts of an import table were placed.
#[derive(Clone, Debug, Default)]
pub struct ImportLayout {
    pub dir_rva: u32,
    pub dir_size: u32,
    /// Per DLL: IAT RVA.
    pub iats: Vec<u32>,
    /// Per DLL: lookup table RVA.
    pub ilts: Vec<u32>,
    /// The whole IAT range.
    pub iat_range: (u32, u32),
}

/// An import directory placed at `base` (descriptors, lookup tables, IATs, names).
pub fn import_blob(
    base: u32,
    plus: bool,
    dlls: &[(&str, Vec<Imp<'_>>)],
) -> (Vec<u8>, ImportLayout) {
    let ptr = if plus { 8 } else { 4 };
    let n = dlls.len() as u32;
    let desc = (n + 1) * 20;
    let tables: u32 = dlls.iter().map(|(_, v)| (v.len() as u32 + 1) * ptr).sum();
    let ilt0 = base + desc;
    let iat0 = ilt0 + tables;
    let names0 = iat0 + tables;
    // Hint/name entries and DLL names.
    let mut names = W::default();
    let mut hn: Vec<Vec<u64>> = Vec::new();
    for (_, imps) in dlls {
        let mut v = Vec::new();
        for i in imps {
            match i {
                Imp::Name(s, hint) => {
                    names.align(2);
                    v.push(u64::from(names0 + names.len()));
                    names.u16(*hint).cstr(s);
                }
                Imp::Ordinal(o) => v.push(if plus { 1 << 63 } else { 1 << 31 } | u64::from(*o)),
            }
        }
        hn.push(v);
    }
    let mut dll_names = Vec::new();
    for (d, _) in dlls {
        dll_names.push(names0 + names.len());
        names.cstr(d);
    }
    let mut w = W::default();
    let mut lay = ImportLayout {
        dir_rva: base,
        dir_size: desc,
        ..Default::default()
    };
    let mut off = 0;
    for (i, (_, imps)) in dlls.iter().enumerate() {
        let ilt = ilt0 + off;
        let iat = iat0 + off;
        w.u32(ilt).u32(0).u32(0).u32(dll_names[i]).u32(iat);
        lay.ilts.push(ilt);
        lay.iats.push(iat);
        off += (imps.len() as u32 + 1) * ptr;
    }
    w.bytes(&[0; 20]);
    for _ in 0..2 {
        for v in &hn {
            for x in v {
                w.ptr(*x, plus);
            }
            w.ptr(0, plus);
        }
    }
    w.bytes(&names.0);
    lay.iat_range = (iat0, tables);
    (w.0, lay)
}

/// An export directory placed at `base`. `funcs` are address-table RVAs (0 =
/// unused slot; a forwarder string is given as `Err(text)`); `names` map a name
/// to an address-table index and must already be sorted.
pub fn export_blob(
    base: u32,
    dll: &str,
    ordinal_base: u32,
    funcs: &[Result<u32, &str>],
    names: &[(&str, u16)],
) -> (Vec<u8>, u32) {
    let nf = funcs.len() as u32;
    let nn = names.len() as u32;
    let eat = base + 40;
    let enpt = eat + nf * 4;
    let eot = enpt + nn * 4;
    let strings0 = eot + nn * 2;
    let mut strings = W::default();
    let dll_rva = strings0;
    strings.cstr(dll);
    let mut name_rvas = Vec::new();
    for (n, _) in names {
        name_rvas.push(strings0 + strings.len());
        strings.cstr(n);
    }
    let mut fwd_rvas = Vec::new();
    for f in funcs {
        if let Err(text) = f {
            fwd_rvas.push(strings0 + strings.len());
            strings.cstr(text);
        }
    }
    let mut w = W::default();
    w.u32(0)
        .u32(0)
        .u32(0)
        .u32(dll_rva)
        .u32(ordinal_base)
        .u32(nf)
        .u32(nn)
        .u32(eat)
        .u32(enpt)
        .u32(eot);
    let mut fw = fwd_rvas.iter();
    for f in funcs {
        match f {
            Ok(r) => w.u32(*r),
            Err(_) => w.u32(*fw.next().unwrap()),
        };
    }
    for r in &name_rvas {
        w.u32(*r);
    }
    for (_, i) in names {
        w.u16(*i);
    }
    w.bytes(&strings.0);
    let size = w.len();
    (w.0, size)
}

/// A base relocation block for `page` with 16-bit entries (type << 12 | offset).
pub fn reloc_block(page: u32, entries: &[u16]) -> Vec<u8> {
    let mut w = W::default();
    let n = entries.len() as u32;
    w.u32(page).u32(8 + n * 2);
    for e in entries {
        w.u16(*e);
    }
    w.0
}

/// Computes the Rich-header checksum the way Microsoft's linker does (used to
/// build valid headers; the algorithm itself is checked against real files).
pub fn rich_checksum(file: &[u8], dans: usize, entries: &[(u32, u32)]) -> u32 {
    let mut sum = dans as u32;
    for (i, b) in file[..dans].iter().enumerate() {
        if (0x3c..0x40).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(*b).rotate_left(i as u32 % 32));
    }
    for (comp, count) in entries {
        sum = sum.wrapping_add(comp.rotate_left(count % 32));
    }
    sum
}

/// A PE32+ image with every data directory populated: imports, delay imports,
/// exports, base relocations, TLS callbacks, load configuration with a CFG
/// table, exception table with unwind data, debug directory, resources and a
/// signature. Used as a seed for mutation testing and fuzzing.
pub fn kitchen_sink() -> Vec<u8> {
    const B: u64 = 0x1_4000_0000;
    let mut b = PeBuilder::new64();
    b.dll_characteristics |= 0x4000;
    b.sections[0].data = vec![0xc3; 0x100];
    let (rd, dt, pd, rs, rl) = (0x2000u32, 0x3000u32, 0x4000u32, 0x5000u32, 0x6000u32);
    let mut r = W::default();
    let (imp, lay) = import_blob(
        rd,
        true,
        &[(
            "KERNEL32.dll",
            vec![Imp::Name("ExitProcess", 1), Imp::Ordinal(5)],
        )],
    );
    r.bytes(&imp).pad_to(0x200);
    let (exp, exp_size) = export_blob(
        rd + 0x200,
        "sink.dll",
        1,
        &[Ok(0x1000), Err("K.Sleep")],
        &[("go", 0), ("zz", 1)],
    );
    r.bytes(&exp).pad_to(0x300);
    r.u64(0)
        .u64(0)
        .u64(B + u64::from(dt) + 0x40)
        .u64(B + u64::from(dt) + 0x20)
        .u32(0)
        .u32(0);
    r.pad_to(0x340);
    let lc = r.len() as usize;
    r.u32(0x94).pad_to(lc + 0x94);
    r.put_u64(lc + 88, B + u64::from(dt) + 0x50);
    r.put_u64(lc + 128, B + u64::from(rd) + 0x440);
    r.put_u64(lc + 136, 2);
    r.put_u32(lc + 144, 0x500);
    r.pad_to(0x440);
    r.u32(0x1000).u32(0x1010);
    r.pad_to(0x480);
    let dbg = r.len() as usize;
    r.bytes(&[0; 28]);
    r.bytes(b"RSDS").bytes(&[7; 16]).u32(1).cstr("sink.pdb");
    r.pad_to(0x500);
    r.u8(0x09)
        .u8(4)
        .u8(2)
        .u8(0)
        .u8(4)
        .u8(0x32)
        .u8(1)
        .u8(0x50)
        .u32(0x1010);
    r.pad_to(0x520);
    // A fragment: unwind data chained to the first function's.
    r.u8(0x21)
        .u8(0)
        .u8(0)
        .u8(0)
        .u32(0x1000)
        .u32(0x1010)
        .u32(rd + 0x500);
    r.pad_to(0x600);
    r.u32(1)
        .u32(rd + 0x680)
        .u32(dt)
        .u32(dt + 8)
        .u32(rd + 0x640)
        .u32(0)
        .u32(0)
        .u32(0);
    r.bytes(&[0; 32]);
    r.pad_to(0x640);
    r.u64(u64::from(rd) + 0x660).u64(0);
    r.pad_to(0x660);
    r.u16(0).cstr("MessageBoxA").pad_to(0x680);
    r.cstr("USER32.dll").pad_to(0x700);
    let mut d = W::default();
    d.u64(0)
        .u64(B + 0x1020)
        .u64(0)
        .u64(0)
        .u64(B + 0x1000)
        .u64(B + 0x1010)
        .u64(0)
        .u64(0)
        .u64(0)
        .u64(0x2b99_2ddf_a232);
    let mut p = W::default();
    p.u32(0x1000)
        .u32(0x1010)
        .u32(rd + 0x500)
        .u32(0x1010)
        .u32(0x1020)
        .u32(rd + 0x520);
    let mut res = W::default();
    res.u32(0)
        .u32(0)
        .u32(0)
        .u16(0)
        .u16(1)
        .u32(10)
        .u32(0x8000_0018);
    res.u32(0).u32(0).u32(0).u16(0).u16(1).u32(1).u32(0x30);
    res.u32(rs + 0x40)
        .u32(4)
        .u32(0)
        .u32(0)
        .pad_to(0x40)
        .bytes(b"data");
    let rel = reloc_block(dt, &[0xa008, 0xa020, 0xa028, 0xa050, 0]);
    let rel_len = rel.len() as u32;
    let rdi = b.section(Sec::new(".rdata", RDATA, r.0.clone()));
    b.section(Sec::new(".data", DATA, d.0));
    b.section(Sec::new(".pdata", RDATA, p.0));
    b.section(Sec::new(".rsrc", RDATA, res.0));
    b.section(Sec::new(".reloc", 0x4200_0040, rel));
    let raw = b.layout()[rdi].raw_ptr;
    // Debug entry: CodeView data right after the entry.
    let mut e = W::default();
    e.u32(0)
        .u32(0)
        .u32(0)
        .u32(2)
        .u32(33)
        .u32(rd + 0x49c)
        .u32(raw + 0x49c);
    r.0[dbg..dbg + 28].copy_from_slice(&e.0);
    b.sections[rdi].data = r.0;
    for (i, rva, size) in [
        (0, rd + 0x200, exp_size),
        (1, lay.dir_rva, lay.dir_size),
        (2, rs, 0x44),
        (3, pd, 24),
        (5, rl, rel_len),
        (6, rd + 0x480, 28),
        (9, rd + 0x300, 40),
        (10, rd + 0x340, 0x94),
        (12, lay.iat_range.0, lay.iat_range.1),
        (13, rd + 0x600, 32),
    ] {
        b.dir(i, rva, size);
    }
    let end = {
        let l = *b.layout().last().unwrap();
        l.raw_ptr + l.raw_size
    };
    let mut c = W::default();
    c.u32(24).u16(0x200).u16(2).bytes(&[0x30; 16]);
    b.trailer = c.0;
    b.dir(4, end, 24);
    b.build()
}
