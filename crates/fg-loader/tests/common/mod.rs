// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Test helper: builds small synthetic ELF files, correct or deliberately broken.
#![allow(dead_code, missing_docs)]

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;

#[derive(Clone, Debug, Default)]
pub struct Phdr {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Phdr {
    pub fn new(p_type: u32, flags: u32) -> Phdr {
        Phdr {
            p_type,
            flags,
            ..Phdr::default()
        }
    }
    pub fn file(mut self, offset: u64, size: u64) -> Phdr {
        self.offset = offset;
        self.filesz = size;
        self
    }
    pub fn mem(mut self, vaddr: u64, size: u64) -> Phdr {
        self.vaddr = vaddr;
        self.memsz = size;
        self
    }
    pub fn align(mut self, align: u64) -> Phdr {
        self.align = align;
        self
    }
}

#[derive(Clone, Debug)]
pub struct ElfBuilder {
    pub class64: bool,
    pub big_endian: bool,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub phoff: Option<u64>,
    pub shoff: u64,
    pub phdrs: Vec<Phdr>,
    pub phnum_override: Option<u16>,
    pub phentsize_override: Option<u16>,
    /// Bytes written at fixed file offsets (the file grows to fit).
    pub blobs: Vec<(u64, Vec<u8>)>,
    /// Minimum total file length.
    pub min_len: usize,
    /// Section headers. When non-empty, a `.shstrtab` is appended automatically
    /// and the table is written after all other content.
    pub sections: Vec<Shdr>,
    pub shnum_override: Option<u16>,
    pub shstrndx_override: Option<u16>,
    pub shentsize_override: Option<u16>,
    /// Value written to section header 0's sh_size / sh_link (for the escapes).
    pub sh0_size: u64,
    pub sh0_link: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Shdr {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
}

impl Shdr {
    pub fn new(name: &str, sh_type: u32) -> Shdr {
        Shdr {
            name: name.to_string(),
            sh_type,
            align: 1,
            ..Shdr::default()
        }
    }
    pub fn at(mut self, offset: u64, size: u64) -> Shdr {
        self.offset = offset;
        self.size = size;
        self
    }
    pub fn addr(mut self, addr: u64) -> Shdr {
        self.addr = addr;
        self
    }
    pub fn flags(mut self, flags: u64) -> Shdr {
        self.flags = flags;
        self
    }
    pub fn link(mut self, link: u32, info: u32) -> Shdr {
        self.link = link;
        self.info = info;
        self
    }
    pub fn entsize(mut self, entsize: u64) -> Shdr {
        self.entsize = entsize;
        self
    }
}

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;
pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

impl Default for ElfBuilder {
    fn default() -> ElfBuilder {
        ElfBuilder {
            class64: true,
            big_endian: false,
            e_type: ET_EXEC,
            machine: EM_X86_64,
            entry: 0x401000,
            phoff: None,
            shoff: 0,
            phdrs: Vec::new(),
            phnum_override: None,
            phentsize_override: None,
            blobs: Vec::new(),
            min_len: 0,
            sections: Vec::new(),
            shnum_override: None,
            shstrndx_override: None,
            shentsize_override: None,
            sh0_size: 0,
            sh0_link: 0,
        }
    }
}

impl ElfBuilder {
    pub fn ehsize(&self) -> u64 {
        if self.class64 { 64 } else { 52 }
    }
    pub fn phentsize(&self) -> u64 {
        u64::from(
            self.phentsize_override
                .unwrap_or(if self.class64 { 56 } else { 32 }),
        )
    }
    pub fn phoff(&self) -> u64 {
        self.phoff.unwrap_or(self.ehsize())
    }

    fn put(&self, buf: &mut Vec<u8>, off: u64, value: u64, size: usize) {
        let off = off as usize;
        if buf.len() < off + size {
            buf.resize(off + size, 0);
        }
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        let src = if self.big_endian {
            &bytes[8 - size..]
        } else {
            &bytes[..size]
        };
        buf[off..off + size].copy_from_slice(src);
    }

    pub fn build(&self) -> Vec<u8> {
        let mut b = vec![0u8; self.ehsize() as usize];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = if self.class64 { 2 } else { 1 };
        b[5] = if self.big_endian { 2 } else { 1 };
        b[6] = 1;
        let w = if self.class64 { 8 } else { 4 };
        let phnum = self.phnum_override.unwrap_or(self.phdrs.len() as u16);
        self.put(&mut b, 16, u64::from(self.e_type), 2);
        self.put(&mut b, 18, u64::from(self.machine), 2);
        self.put(&mut b, 20, 1, 4);
        let (entry, phoff, shoff, flags, ehsize) = if self.class64 {
            (24, 32, 40, 48, 52)
        } else {
            (24, 28, 32, 36, 40)
        };
        self.put(&mut b, entry, self.entry, w);
        self.put(
            &mut b,
            phoff,
            if self.phdrs.is_empty() && self.phnum_override.is_none() {
                0
            } else {
                self.phoff()
            },
            w,
        );
        self.put(&mut b, shoff, self.shoff, w);
        self.put(&mut b, flags, 0, 4);
        self.put(&mut b, ehsize, self.ehsize(), 2);
        self.put(&mut b, ehsize + 2, self.phentsize(), 2);
        self.put(&mut b, ehsize + 4, u64::from(phnum), 2);
        self.put(&mut b, ehsize + 6, if self.class64 { 64 } else { 40 }, 2);

        for (i, p) in self.phdrs.iter().enumerate() {
            let base = self.phoff() + i as u64 * self.phentsize();
            if self.class64 {
                self.put(&mut b, base, u64::from(p.p_type), 4);
                self.put(&mut b, base + 4, u64::from(p.flags), 4);
                self.put(&mut b, base + 8, p.offset, 8);
                self.put(&mut b, base + 16, p.vaddr, 8);
                self.put(&mut b, base + 24, p.vaddr, 8);
                self.put(&mut b, base + 32, p.filesz, 8);
                self.put(&mut b, base + 40, p.memsz, 8);
                self.put(&mut b, base + 48, p.align, 8);
            } else {
                self.put(&mut b, base, u64::from(p.p_type), 4);
                self.put(&mut b, base + 4, p.offset, 4);
                self.put(&mut b, base + 8, p.vaddr, 4);
                self.put(&mut b, base + 12, p.vaddr, 4);
                self.put(&mut b, base + 16, p.filesz, 4);
                self.put(&mut b, base + 20, p.memsz, 4);
                self.put(&mut b, base + 24, u64::from(p.flags), 4);
                self.put(&mut b, base + 28, p.align, 4);
            }
        }
        for (off, bytes) in &self.blobs {
            let off = *off as usize;
            if b.len() < off + bytes.len() {
                b.resize(off + bytes.len(), 0);
            }
            b[off..off + bytes.len()].copy_from_slice(bytes);
        }
        if b.len() < self.min_len {
            b.resize(self.min_len, 0);
        }
        if !self.sections.is_empty() {
            self.write_sections(&mut b);
        }
        b
    }

    fn write_sections(&self, b: &mut Vec<u8>) {
        // Names: index 0 is the empty string.
        let mut names = vec![0u8];
        let mut name_off = Vec::new();
        let all: Vec<Shdr> = self
            .sections
            .iter()
            .cloned()
            .chain(std::iter::once(Shdr::new(".shstrtab", SHT_STRTAB)))
            .collect();
        for s in &all {
            name_off.push(names.len() as u64);
            names.extend_from_slice(s.name.as_bytes());
            names.push(0);
        }
        let align8 = |n: usize| n.div_ceil(8) * 8;
        let strtab_off = align8(b.len());
        b.resize(strtab_off, 0);
        b.extend_from_slice(&names);
        let shoff = align8(b.len()) as u64;
        b.resize(shoff as usize, 0);
        let ent: u64 = if self.class64 { 64 } else { 40 };
        let w = if self.class64 { 8 } else { 4 };
        // Header 0 (null section) carries the escape values.
        let mut entries: Vec<(u64, Shdr)> = vec![(
            0,
            Shdr {
                size: self.sh0_size,
                link: self.sh0_link,
                align: 0,
                ..Shdr::default()
            },
        )];
        for (i, s) in all.iter().enumerate() {
            let mut s = s.clone();
            if i == all.len() - 1 {
                s.offset = strtab_off as u64;
                s.size = names.len() as u64;
            }
            entries.push((name_off[i], s));
        }
        for (i, (name, s)) in entries.iter().enumerate() {
            let base = shoff + i as u64 * ent;
            let (f, a, o, z, l, inf, al, es) = if self.class64 {
                (8, 16, 24, 32, 40, 44, 48, 56)
            } else {
                (8, 12, 16, 20, 24, 28, 32, 36)
            };
            self.put(b, base, *name, 4);
            self.put(b, base + 4, u64::from(s.sh_type), 4);
            self.put(b, base + f, s.flags, w);
            self.put(b, base + a, s.addr, w);
            self.put(b, base + o, s.offset, w);
            self.put(b, base + z, s.size, w);
            self.put(b, base + l, u64::from(s.link), 4);
            self.put(b, base + inf, u64::from(s.info), 4);
            self.put(b, base + al, s.align, w);
            self.put(b, base + es, s.entsize, w);
        }
        let (shoff_at, ehsize_at) = if self.class64 { (40, 52) } else { (32, 40) };
        self.put(b, shoff_at, shoff, w);
        self.put(
            b,
            ehsize_at + 6,
            u64::from(self.shentsize_override.unwrap_or(ent as u16)),
            2,
        );
        self.put(
            b,
            ehsize_at + 8,
            u64::from(self.shnum_override.unwrap_or(entries.len() as u16)),
            2,
        );
        self.put(
            b,
            ehsize_at + 10,
            u64::from(self.shstrndx_override.unwrap_or(all.len() as u16)),
            2,
        );
    }

    /// Encodes ELF64 symbol entries: (st_name, info, shndx, value, size).
    pub fn symbols64(&self, syms: &[(u32, u8, u16, u64, u64)]) -> Vec<u8> {
        let mut out = vec![0u8; 24]; // null symbol
        for &(name, info, shndx, value, size) in syms {
            let at = out.len() as u64;
            self.put(&mut out, at, u64::from(name), 4);
            self.put(&mut out, at + 4, u64::from(info), 1);
            self.put(&mut out, at + 5, 0, 1);
            self.put(&mut out, at + 6, u64::from(shndx), 2);
            self.put(&mut out, at + 8, value, 8);
            self.put(&mut out, at + 16, size, 8);
        }
        out
    }

    /// Encodes dynamic entries (a DT_NULL terminator is appended when `terminate`).
    pub fn dynamic(&self, entries: &[(i64, u64)], terminate: bool) -> Vec<u8> {
        let w = if self.class64 { 8 } else { 4 };
        let mut out = Vec::new();
        let mut all: Vec<(i64, u64)> = entries.to_vec();
        if terminate {
            all.push((0, 0));
        }
        for (tag, val) in all {
            let start = out.len() as u64;
            self.put(&mut out, start, tag as u64, w);
            self.put(&mut out, start + w as u64, val, w);
        }
        out
    }
}

/// A minimal, valid, non-PIE x86-64 executable: one R-X LOAD containing the
/// entry point, a non-executable GNU_STACK, and enough bytes to back the LOAD.
pub fn minimal_exec() -> ElfBuilder {
    ElfBuilder {
        phdrs: vec![
            Phdr::new(PT_LOAD, PF_R | PF_X)
                .file(0, 0x200)
                .mem(0x400000, 0x200)
                .align(0x1000),
            Phdr::new(PT_GNU_STACK, PF_R | PF_W).align(0x10),
        ],
        entry: 0x400100,
        min_len: 0x200,
        ..ElfBuilder::default()
    }
}

/// Anomaly codes found in a load result.
pub fn codes(b: &fg_loader::LoadedBinary) -> Vec<&'static str> {
    b.anomalies.iter().map(|a| a.code).collect()
}
pub mod pe;
