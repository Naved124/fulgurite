// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! ELF constants (System V gABI, plus the GNU extensions seen on Linux).
#![allow(missing_docs)]

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const EI_NIDENT: u64 = 16;
pub const EI_CLASS: u64 = 4;
pub const EI_DATA: u64 = 5;
pub const EI_VERSION: u64 = 6;
pub const EI_OSABI: u64 = 7;
pub const EI_ABIVERSION: u64 = 8;

pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;
pub const EV_CURRENT: u32 = 1;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_386: u16 = 3;
pub const EM_PPC: u16 = 20;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_L1OM: u16 = 180;
pub const EM_K1OM: u16 = 181;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;

pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_GNU: u8 = 3;
pub const ELFOSABI_FREEBSD: u8 = 9;

/// `e_phnum` value meaning "the real count is in section header 0's `sh_info`".
pub const PN_XNUM: u16 = 0xffff;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;
pub const PT_GNU_SFRAME: u32 = 0x6474_e554;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_PIE: u64 = 0x0800_0000;

/// Name of a program-header type as `readelf -l` prints it, if known.
pub fn p_type_name(p_type: u32) -> Option<&'static str> {
    Some(match p_type {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_SHLIB => "SHLIB",
        PT_PHDR => "PHDR",
        PT_TLS => "TLS",
        PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        PT_GNU_PROPERTY => "GNU_PROPERTY",
        PT_GNU_SFRAME => "GNU_SFRAME",
        _ => return None,
    })
}

/// Name of an `e_type` value.
pub fn e_type_name(e_type: u16) -> &'static str {
    match e_type {
        ET_NONE => "NONE",
        ET_REL => "REL",
        ET_EXEC => "EXEC",
        ET_DYN => "DYN",
        ET_CORE => "CORE",
        _ => "unknown",
    }
}

/// Name of an `EI_OSABI` value.
pub fn osabi_name(osabi: u8) -> &'static str {
    match osabi {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "GNU/Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        97 => "ARM",
        255 => "standalone",
        _ => "unknown",
    }
}

// ---- Sections -------------------------------------------------------------

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
/// `e_shstrndx` / `st_shndx` escape: the real index lives elsewhere.
pub const SHN_XINDEX: u16 = 0xffff;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_RELR: u32 = 19;
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6fff_fff5;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
pub const SHT_GNU_LIBLIST: u32 = 0x6fff_fff7;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_GNU_RETAIN: u64 = 0x20_0000;
pub const SHF_GNU_MBIND: u64 = 0x100_0000;
pub const SHF_MASKOS: u64 = 0x0ff0_0000;
pub const SHF_X86_64_LARGE: u64 = 0x1000_0000;
pub const SHF_PPC_VLE: u64 = 0x1000_0000;
pub const SHF_ARM_PURECODE: u64 = 0x2000_0000;
pub const SHF_EXCLUDE: u64 = 0x8000_0000;
pub const SHF_MASKPROC: u64 = 0xf000_0000;

/// Section type name as `readelf -S` prints it, if known. Machine-specific types
/// are only named for the machine that defines them.
pub fn sh_type_name(sh_type: u32, machine: u16) -> Option<&'static str> {
    Some(match sh_type {
        SHT_NULL => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_RELA => "RELA",
        SHT_HASH => "HASH",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_NOTE => "NOTE",
        SHT_NOBITS => "NOBITS",
        SHT_REL => "REL",
        SHT_SHLIB => "SHLIB",
        SHT_DYNSYM => "DYNSYM",
        SHT_INIT_ARRAY => "INIT_ARRAY",
        SHT_FINI_ARRAY => "FINI_ARRAY",
        SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
        SHT_GROUP => "GROUP",
        SHT_SYMTAB_SHNDX => "SYMTAB SECTION INDICES",
        SHT_RELR => "RELR",
        SHT_GNU_ATTRIBUTES => "GNU_ATTRIBUTES",
        SHT_GNU_HASH => "GNU_HASH",
        SHT_GNU_LIBLIST => "GNU_LIBLIST",
        SHT_GNU_VERDEF => "VERDEF",
        SHT_GNU_VERNEED => "VERNEED",
        SHT_GNU_VERSYM => "VERSYM",
        SHT_X86_64_UNWIND if machine == EM_X86_64 => "X86_64_UNWIND",
        _ => return None,
    })
}

/// Section flags as the letters `readelf -S` prints, by readelf's own rules
/// (binutils `get_elf_section_flags`, the same from 2.42 to 2.47):
///
/// - bits are taken lowest first, one letter each: `W A X M S I L O G T C E`;
/// - `l` (large) only on x86-64, `y` (pure code) only on ARM, `v` (VLE) only on
///   PowerPC;
/// - OS-specific bits depend on the file's `EI_OSABI`: `R` (`SHF_GNU_RETAIN`) only
///   for GNU and FreeBSD, `D` (`SHF_GNU_MBIND`) for those and System V, because old
///   GNU tools left `EI_OSABI` at 0. Any other OS-specific bit is one `o` for the
///   whole OS range, and the rest of that range is not looked at;
/// - processor-specific bits without a letter are one `p` for the whole range in the
///   same way, and any other bit is `x`.
///
/// So `o`, `p` and `x` do not say which bit was set: the raw value is `sh_flags`.
pub fn sh_flags_letters(flags: u64, machine: u16, osabi: u8) -> String {
    let gnu = matches!(osabi, ELFOSABI_GNU | ELFOSABI_FREEBSD);
    let mut rest = flags;
    let mut out = String::new();
    while rest != 0 {
        let flag = rest & rest.wrapping_neg();
        rest &= !flag;
        let letter = match flag {
            SHF_WRITE => 'W',
            SHF_ALLOC => 'A',
            SHF_EXECINSTR => 'X',
            SHF_MERGE => 'M',
            SHF_STRINGS => 'S',
            SHF_INFO_LINK => 'I',
            SHF_LINK_ORDER => 'L',
            SHF_OS_NONCONFORMING => 'O',
            SHF_GROUP => 'G',
            SHF_TLS => 'T',
            SHF_EXCLUDE => 'E',
            SHF_COMPRESSED => 'C',
            SHF_X86_64_LARGE if matches!(machine, EM_X86_64 | EM_L1OM | EM_K1OM) => 'l',
            SHF_ARM_PURECODE if machine == EM_ARM => 'y',
            SHF_PPC_VLE if machine == EM_PPC => 'v',
            SHF_GNU_RETAIN if gnu => 'R',
            SHF_GNU_MBIND if gnu || osabi == ELFOSABI_NONE => 'D',
            _ if flag & SHF_MASKOS != 0 => {
                rest &= !SHF_MASKOS;
                'o'
            }
            _ if flag & SHF_MASKPROC != 0 => {
                rest &= !SHF_MASKPROC;
                'p'
            }
            _ => 'x',
        };
        out.push(letter);
    }
    out
}

// ---- Symbols --------------------------------------------------------------

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_GNU_UNIQUE: u8 = 10;

pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

/// Symbol type name as `readelf -s` prints it.
pub fn st_type_name(t: u8) -> &'static str {
    match t {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        STT_GNU_IFUNC => "IFUNC",
        _ => "UNKNOWN",
    }
}

/// Symbol binding name as `readelf -s` prints it.
pub fn st_bind_name(b: u8) -> &'static str {
    match b {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        STB_GNU_UNIQUE => "UNIQUE",
        _ => "UNKNOWN",
    }
}

/// Symbol visibility name as `readelf -s` prints it.
pub fn st_vis_name(v: u8) -> &'static str {
    match v {
        STV_DEFAULT => "DEFAULT",
        STV_INTERNAL => "INTERNAL",
        STV_HIDDEN => "HIDDEN",
        _ => "PROTECTED",
    }
}

// ---- Dynamic tags used to find symbols without section headers -------------

pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_fff0;
pub const DT_VERDEF: i64 = 0x6fff_fffc;
pub const DT_VERDEFNUM: i64 = 0x6fff_fffd;
pub const DT_VERNEED: i64 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

/// `vd_flags` bit marking the version definition that names the file itself.
pub const VER_FLG_BASE: u16 = 0x1;
/// `versym` bit marking a hidden (non-default) version.
pub const VERSYM_HIDDEN: u16 = 0x8000;

pub const DT_PLTRELSZ: i64 = 2;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_PLTREL: i64 = 20;
pub const DT_JMPREL: i64 = 23;

// ---- Dynamic tags: libraries, search paths, relocation tables ---------------

pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_RELAENT: i64 = 9;
pub const DT_RELENT: i64 = 19;
pub const DT_TEXTREL: i64 = 22;
pub const DT_RUNPATH: i64 = 29;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_PREINIT_ARRAY: i64 = 32;
pub const DT_PREINIT_ARRAYSZ: i64 = 33;
pub const DF_TEXTREL: u64 = 0x4;

// ---- Notes ------------------------------------------------------------------

pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_HWCAP: u32 = 2;
pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_GOLD_VERSION: u32 = 4;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// `.note.package` (systemd/Fedora packaging metadata, owner `FDO`): a JSON string.
pub const NT_FDO_PACKAGING_METADATA: u32 = 0xcafe_1a7e;
/// Go toolchain build ID (owner `Go`).
pub const NT_GO_BUILDID: u32 = 4;

pub const GNU_PROPERTY_STACK_SIZE: u32 = 1;
pub const GNU_PROPERTY_NO_COPY_ON_PROTECTED: u32 = 2;
pub const GNU_PROPERTY_MEMORY_SEAL: u32 = 3;
pub const GNU_PROPERTY_1_NEEDED: u32 = 0xb000_8000;
pub const GNU_PROPERTY_LOPROC: u32 = 0xc000_0000;
pub const GNU_PROPERTY_LOUSER: u32 = 0xe000_0000;
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
pub const GNU_PROPERTY_X86_FEATURE_2_NEEDED: u32 = 0xc000_8001;
pub const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
pub const GNU_PROPERTY_X86_FEATURE_2_USED: u32 = 0xc001_0001;
pub const GNU_PROPERTY_X86_ISA_1_USED: u32 = 0xc001_0002;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
pub const GNU_PROPERTY_RISCV_FEATURE_1_AND: u32 = 0xc000_0000;

pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1 << 0;
pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 1 << 1;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1 << 0;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 1 << 1;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_GCS: u32 = 1 << 2;
pub const GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED: u32 = 1 << 0;
pub const GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS: u32 = 1 << 1;
pub const GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_FUNC_SIG: u32 = 1 << 2;

/// Bit names of `GNU_PROPERTY_X86_FEATURE_1_AND`, as `readelf -n` prints them.
pub const X86_FEATURE_1_NAMES: &[(u32, &str)] = &[
    (1 << 0, "IBT"),
    (1 << 1, "SHSTK"),
    (1 << 2, "LAM_U48"),
    (1 << 3, "LAM_U57"),
];
/// Bit names of the x86 ISA level properties.
pub const X86_ISA_1_NAMES: &[(u32, &str)] = &[
    (1 << 0, "x86-64-baseline"),
    (1 << 1, "x86-64-v2"),
    (1 << 2, "x86-64-v3"),
    (1 << 3, "x86-64-v4"),
];
/// Bit names of the x86 `FEATURE_2` (used / needed) properties.
pub const X86_FEATURE_2_NAMES: &[(u32, &str)] = &[
    (1 << 0, "x86"),
    (1 << 1, "x87"),
    (1 << 2, "MMX"),
    (1 << 3, "XMM"),
    (1 << 4, "YMM"),
    (1 << 5, "ZMM"),
    (1 << 6, "FXSR"),
    (1 << 7, "XSAVE"),
    (1 << 8, "XSAVEOPT"),
    (1 << 9, "XSAVEC"),
    (1 << 10, "TMM"),
    (1 << 11, "MASK"),
];
pub const GNU_PROPERTY_X86_COMPAT_ISA_1_USED: u32 = 0xc000_0000;
pub const GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED: u32 = 0xc000_0001;
pub const GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED: u32 = 0xc000_8000;
pub const GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED: u32 = 0xc001_0000;
pub const GNU_PROPERTY_HIPROC: u32 = 0xdfff_ffff;
pub const GNU_PROPERTY_UINT32_AND_LO: u32 = 0xb000_0000;
pub const GNU_PROPERTY_UINT32_AND_HI: u32 = 0xb000_7fff;
pub const GNU_PROPERTY_UINT32_OR_HI: u32 = 0xb000_ffff;

/// Bit names of the x86 ISA properties written by older binutils releases (`COMPAT_ISA_1`).
pub const X86_COMPAT_ISA_1_NAMES: &[(u32, &str)] = &[
    (1 << 0, "i486"),
    (1 << 1, "586"),
    (1 << 2, "686"),
    (1 << 3, "SSE"),
    (1 << 4, "SSE2"),
    (1 << 5, "SSE3"),
    (1 << 6, "SSSE3"),
    (1 << 7, "SSE4_1"),
    (1 << 8, "SSE4_2"),
    (1 << 9, "AVX"),
    (1 << 10, "AVX2"),
    (1 << 11, "AVX512F"),
    (1 << 12, "AVX512CD"),
    (1 << 13, "AVX512ER"),
    (1 << 14, "AVX512PF"),
    (1 << 15, "AVX512VL"),
    (1 << 16, "AVX512DQ"),
    (1 << 17, "AVX512BW"),
];
/// Bit names of the second, also superseded, x86 ISA encoding (`COMPAT_2_ISA_1`).
pub const X86_COMPAT_2_ISA_1_NAMES: &[(u32, &str)] = &[
    (1 << 0, "CMOV"),
    (1 << 1, "SSE"),
    (1 << 2, "SSE2"),
    (1 << 3, "SSE3"),
    (1 << 4, "SSSE3"),
    (1 << 5, "SSE4_1"),
    (1 << 6, "SSE4_2"),
    (1 << 7, "AVX"),
    (1 << 8, "AVX2"),
    (1 << 9, "FMA"),
    (1 << 10, "AVX512F"),
    (1 << 11, "AVX512CD"),
    (1 << 12, "AVX512ER"),
    (1 << 13, "AVX512PF"),
    (1 << 14, "AVX512VL"),
    (1 << 15, "AVX512DQ"),
    (1 << 16, "AVX512BW"),
    (1 << 17, "AVX512_4FMAPS"),
    (1 << 18, "AVX512_4VNNIW"),
    (1 << 19, "AVX512_BITALG"),
    (1 << 20, "AVX512_IFMA"),
    (1 << 21, "AVX512_VBMI"),
    (1 << 22, "AVX512_VBMI2"),
    (1 << 23, "AVX512_VNNI"),
    (1 << 24, "AVX512_BF16"),
];
/// Bit names of `GNU_PROPERTY_1_NEEDED`.
pub const GNU_1_NEEDED_NAMES: &[(u32, &str)] = &[(1 << 0, "indirect external access")];

/// Bit names of `GNU_PROPERTY_AARCH64_FEATURE_1_AND`.
pub const AARCH64_FEATURE_1_NAMES: &[(u32, &str)] =
    &[(1 << 0, "BTI"), (1 << 1, "PAC"), (1 << 2, "GCS")];
/// Bit names of `GNU_PROPERTY_RISCV_FEATURE_1_AND`.
pub const RISCV_FEATURE_1_NAMES: &[(u32, &str)] = &[
    (1 << 0, "CFI_LP_UNLABELED"),
    (1 << 1, "CFI_SS"),
    (1 << 2, "CFI_LP_FUNC_SIG"),
];

/// Description of a GNU note type as `readelf -n` prints it.
pub fn gnu_note_type_name(n_type: u32) -> Option<&'static str> {
    Some(match n_type {
        NT_GNU_ABI_TAG => "NT_GNU_ABI_TAG (ABI version tag)",
        NT_GNU_HWCAP => "NT_GNU_HWCAP (DSO-supplied software HWCAP info)",
        NT_GNU_BUILD_ID => "NT_GNU_BUILD_ID (unique build ID bitstring)",
        NT_GNU_GOLD_VERSION => "NT_GNU_GOLD_VERSION (gold version)",
        NT_GNU_PROPERTY_TYPE_0 => "NT_GNU_PROPERTY_TYPE_0",
        _ => return None,
    })
}

// ---- Relocation types ---------------------------------------------------------

/// Relocation type name as `readelf -r` prints it, for the architectures
/// Fulgurite targets. `None` for types not listed here.
pub fn r_type_name(machine: u16, r_type: u32) -> Option<&'static str> {
    let table: &[&str] = match machine {
        EM_X86_64 => X86_64_RELOCS,
        EM_386 => I386_RELOCS,
        EM_RISCV => RISCV_RELOCS,
        EM_AARCH64 => return aarch64_reloc_name(r_type),
        EM_ARM => return arm_reloc_name(r_type),
        _ => return None,
    };
    match (machine, r_type) {
        (EM_X86_64 | EM_386, 250) => Some(if machine == EM_386 {
            "R_386_GNU_VTINHERIT"
        } else {
            "R_X86_64_GNU_VTINHERIT"
        }),
        (EM_X86_64 | EM_386, 251) => Some(if machine == EM_386 {
            "R_386_GNU_VTENTRY"
        } else {
            "R_X86_64_GNU_VTENTRY"
        }),
        _ => table
            .get(r_type as usize)
            .copied()
            .filter(|n| !n.is_empty()),
    }
}

/// Indexed by type number; empty strings are unassigned numbers.
const X86_64_RELOCS: &[&str] = &[
    "R_X86_64_NONE",
    "R_X86_64_64",
    "R_X86_64_PC32",
    "R_X86_64_GOT32",
    "R_X86_64_PLT32",
    "R_X86_64_COPY",
    "R_X86_64_GLOB_DAT",
    "R_X86_64_JUMP_SLOT",
    "R_X86_64_RELATIVE",
    "R_X86_64_GOTPCREL",
    "R_X86_64_32",
    "R_X86_64_32S",
    "R_X86_64_16",
    "R_X86_64_PC16",
    "R_X86_64_8",
    "R_X86_64_PC8",
    "R_X86_64_DTPMOD64",
    "R_X86_64_DTPOFF64",
    "R_X86_64_TPOFF64",
    "R_X86_64_TLSGD",
    "R_X86_64_TLSLD",
    "R_X86_64_DTPOFF32",
    "R_X86_64_GOTTPOFF",
    "R_X86_64_TPOFF32",
    "R_X86_64_PC64",
    "R_X86_64_GOTOFF64",
    "R_X86_64_GOTPC32",
    "R_X86_64_GOT64",
    "R_X86_64_GOTPCREL64",
    "R_X86_64_GOTPC64",
    "R_X86_64_GOTPLT64",
    "R_X86_64_PLTOFF64",
    "R_X86_64_SIZE32",
    "R_X86_64_SIZE64",
    "R_X86_64_GOTPC32_TLSDESC",
    "R_X86_64_TLSDESC_CALL",
    "R_X86_64_TLSDESC",
    "R_X86_64_IRELATIVE",
    "R_X86_64_RELATIVE64",
    "",
    "",
    "R_X86_64_GOTPCRELX",
    "R_X86_64_REX_GOTPCRELX",
    "R_X86_64_CODE_4_GOTPCRELX",
    "R_X86_64_CODE_4_GOTTPOFF",
    "R_X86_64_CODE_4_GOTPC32_TLSDESC",
    "R_X86_64_CODE_5_GOTPCRELX",
    "R_X86_64_CODE_5_GOTTPOFF",
    "R_X86_64_CODE_5_GOTPC32_TLSDESC",
    "R_X86_64_CODE_6_GOTPCRELX",
    "R_X86_64_CODE_6_GOTTPOFF",
    "R_X86_64_CODE_6_GOTPC32_TLSDESC",
];

const I386_RELOCS: &[&str] = &[
    "R_386_NONE",
    "R_386_32",
    "R_386_PC32",
    "R_386_GOT32",
    "R_386_PLT32",
    "R_386_COPY",
    "R_386_GLOB_DAT",
    "R_386_JUMP_SLOT",
    "R_386_RELATIVE",
    "R_386_GOTOFF",
    "R_386_GOTPC",
    "R_386_32PLT",
    "",
    "",
    "R_386_TLS_TPOFF",
    "R_386_TLS_IE",
    "R_386_TLS_GOTIE",
    "R_386_TLS_LE",
    "R_386_TLS_GD",
    "R_386_TLS_LDM",
    "R_386_16",
    "R_386_PC16",
    "R_386_8",
    "R_386_PC8",
    "R_386_TLS_GD_32",
    "R_386_TLS_GD_PUSH",
    "R_386_TLS_GD_CALL",
    "R_386_TLS_GD_POP",
    "R_386_TLS_LDM_32",
    "R_386_TLS_LDM_PUSH",
    "R_386_TLS_LDM_CALL",
    "R_386_TLS_LDM_POP",
    "R_386_TLS_LDO_32",
    "R_386_TLS_IE_32",
    "R_386_TLS_LE_32",
    "R_386_TLS_DTPMOD32",
    "R_386_TLS_DTPOFF32",
    "R_386_TLS_TPOFF32",
    "R_386_SIZE32",
    "R_386_TLS_GOTDESC",
    "R_386_TLS_DESC_CALL",
    "R_386_TLS_DESC",
    "R_386_IRELATIVE",
    "R_386_GOT32X",
];

const RISCV_RELOCS: &[&str] = &[
    "R_RISCV_NONE",
    "R_RISCV_32",
    "R_RISCV_64",
    "R_RISCV_RELATIVE",
    "R_RISCV_COPY",
    "R_RISCV_JUMP_SLOT",
    "R_RISCV_TLS_DTPMOD32",
    "R_RISCV_TLS_DTPMOD64",
    "R_RISCV_TLS_DTPREL32",
    "R_RISCV_TLS_DTPREL64",
    "R_RISCV_TLS_TPREL32",
    "R_RISCV_TLS_TPREL64",
    "R_RISCV_TLSDESC",
    "",
    "",
    "",
    "R_RISCV_BRANCH",
    "R_RISCV_JAL",
    "R_RISCV_CALL",
    "R_RISCV_CALL_PLT",
    "R_RISCV_GOT_HI20",
    "R_RISCV_TLS_GOT_HI20",
    "R_RISCV_TLS_GD_HI20",
    "R_RISCV_PCREL_HI20",
    "R_RISCV_PCREL_LO12_I",
    "R_RISCV_PCREL_LO12_S",
    "R_RISCV_HI20",
    "R_RISCV_LO12_I",
    "R_RISCV_LO12_S",
    "R_RISCV_TPREL_HI20",
    "R_RISCV_TPREL_LO12_I",
    "R_RISCV_TPREL_LO12_S",
    "R_RISCV_TPREL_ADD",
    "R_RISCV_ADD8",
    "R_RISCV_ADD16",
    "R_RISCV_ADD32",
    "R_RISCV_ADD64",
    "R_RISCV_SUB8",
    "R_RISCV_SUB16",
    "R_RISCV_SUB32",
    "R_RISCV_SUB64",
    "",
    "",
    "R_RISCV_ALIGN",
    "R_RISCV_RVC_BRANCH",
    "R_RISCV_RVC_JUMP",
    "",
    "",
    "",
    "",
    "",
    "R_RISCV_RELAX",
    "R_RISCV_SUB6",
    "R_RISCV_SET6",
    "R_RISCV_SET8",
    "R_RISCV_SET16",
    "R_RISCV_SET32",
    "R_RISCV_32_PCREL",
    "R_RISCV_IRELATIVE",
    "R_RISCV_PLT32",
    "R_RISCV_SET_ULEB128",
    "R_RISCV_SUB_ULEB128",
];

fn aarch64_reloc_name(r_type: u32) -> Option<&'static str> {
    Some(match r_type {
        0 | 256 => "R_AARCH64_NONE",
        257 => "R_AARCH64_ABS64",
        258 => "R_AARCH64_ABS32",
        259 => "R_AARCH64_ABS16",
        260 => "R_AARCH64_PREL64",
        261 => "R_AARCH64_PREL32",
        262 => "R_AARCH64_PREL16",
        263 => "R_AARCH64_MOVW_UABS_G0",
        264 => "R_AARCH64_MOVW_UABS_G0_NC",
        265 => "R_AARCH64_MOVW_UABS_G1",
        266 => "R_AARCH64_MOVW_UABS_G1_NC",
        267 => "R_AARCH64_MOVW_UABS_G2",
        268 => "R_AARCH64_MOVW_UABS_G2_NC",
        269 => "R_AARCH64_MOVW_UABS_G3",
        270 => "R_AARCH64_MOVW_SABS_G0",
        271 => "R_AARCH64_MOVW_SABS_G1",
        272 => "R_AARCH64_MOVW_SABS_G2",
        273 => "R_AARCH64_LD_PREL_LO19",
        274 => "R_AARCH64_ADR_PREL_LO21",
        275 => "R_AARCH64_ADR_PREL_PG_HI21",
        276 => "R_AARCH64_ADR_PREL_PG_HI21_NC",
        277 => "R_AARCH64_ADD_ABS_LO12_NC",
        278 => "R_AARCH64_LDST8_ABS_LO12_NC",
        279 => "R_AARCH64_TSTBR14",
        280 => "R_AARCH64_CONDBR19",
        282 => "R_AARCH64_JUMP26",
        283 => "R_AARCH64_CALL26",
        284 => "R_AARCH64_LDST16_ABS_LO12_NC",
        285 => "R_AARCH64_LDST32_ABS_LO12_NC",
        286 => "R_AARCH64_LDST64_ABS_LO12_NC",
        299 => "R_AARCH64_LDST128_ABS_LO12_NC",
        311 => "R_AARCH64_GOT_LD_PREL19",
        313 => "R_AARCH64_ADR_GOT_PAGE",
        314 => "R_AARCH64_LD64_GOT_LO12_NC",
        1024 => "R_AARCH64_COPY",
        1025 => "R_AARCH64_GLOB_DAT",
        1026 => "R_AARCH64_JUMP_SLOT",
        1027 => "R_AARCH64_RELATIVE",
        1031 => "R_AARCH64_TLSDESC",
        1032 => "R_AARCH64_IRELATIVE",
        _ => return None,
    })
}

fn arm_reloc_name(r_type: u32) -> Option<&'static str> {
    Some(match r_type {
        0 => "R_ARM_NONE",
        2 => "R_ARM_ABS32",
        3 => "R_ARM_REL32",
        10 => "R_ARM_THM_CALL",
        13 => "R_ARM_TLS_DESC",
        17 => "R_ARM_TLS_DTPMOD32",
        18 => "R_ARM_TLS_DTPOFF32",
        19 => "R_ARM_TLS_TPOFF32",
        20 => "R_ARM_COPY",
        21 => "R_ARM_GLOB_DAT",
        22 => "R_ARM_JUMP_SLOT",
        23 => "R_ARM_RELATIVE",
        24 => "R_ARM_GOTOFF32",
        25 => "R_ARM_BASE_PREL",
        26 => "R_ARM_GOT_BREL",
        28 => "R_ARM_CALL",
        29 => "R_ARM_JUMP24",
        30 => "R_ARM_THM_JUMP24",
        42 => "R_ARM_PREL31",
        43 => "R_ARM_MOVW_ABS_NC",
        44 => "R_ARM_MOVT_ABS",
        47 => "R_ARM_THM_MOVW_ABS_NC",
        48 => "R_ARM_THM_MOVT_ABS",
        160 => "R_ARM_IRELATIVE",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WA: u64 = SHF_WRITE | SHF_ALLOC;
    const SOLARIS: u8 = 6;

    #[test]
    fn generic_flags_in_bit_order() {
        let all = SHF_WRITE
            | SHF_ALLOC
            | SHF_EXECINSTR
            | SHF_MERGE
            | SHF_STRINGS
            | SHF_INFO_LINK
            | SHF_LINK_ORDER
            | SHF_OS_NONCONFORMING
            | SHF_GROUP
            | SHF_TLS
            | SHF_COMPRESSED
            | SHF_EXCLUDE;
        assert_eq!(
            sh_flags_letters(all, EM_X86_64, ELFOSABI_NONE),
            "WAXMSILOGTCE"
        );
        assert_eq!(sh_flags_letters(0, EM_X86_64, ELFOSABI_NONE), "");
    }

    #[test]
    fn retain_is_named_only_for_gnu_and_freebsd() {
        let f = WA | SHF_GNU_RETAIN;
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_GNU), "WAR");
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_FREEBSD), "WAR");
        // Ubuntu 24.04's /bin/cat: a System V file with a retained section.
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_NONE), "WAo");
        assert_eq!(sh_flags_letters(f, EM_X86_64, SOLARIS), "WAo");
    }

    #[test]
    fn mbind_is_named_for_system_v_too() {
        let f = SHF_ALLOC | SHF_GNU_MBIND;
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_GNU), "AD");
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_NONE), "AD");
        assert_eq!(sh_flags_letters(f, EM_X86_64, SOLARIS), "Ao");
    }

    #[test]
    fn one_o_covers_the_whole_os_range() {
        // On System V the lower bit (retain) is an `o`, which ends the OS range,
        // so mbind is not shown either.
        let f = SHF_GNU_RETAIN | SHF_GNU_MBIND;
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_NONE), "o");
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_GNU), "RD");
        assert_eq!(
            sh_flags_letters(0x0010_0000 | 0x0040_0000, EM_X86_64, ELFOSABI_GNU),
            "o"
        );
    }

    #[test]
    fn machine_specific_flags() {
        assert_eq!(
            sh_flags_letters(SHF_ALLOC | SHF_X86_64_LARGE, EM_X86_64, 0),
            "Al"
        );
        assert_eq!(
            sh_flags_letters(SHF_ALLOC | SHF_X86_64_LARGE, EM_K1OM, 0),
            "Al"
        );
        assert_eq!(
            sh_flags_letters(SHF_EXECINSTR | SHF_ARM_PURECODE, EM_ARM, 0),
            "Xy"
        );
        assert_eq!(
            sh_flags_letters(SHF_EXECINSTR | SHF_PPC_VLE, EM_PPC, 0),
            "Xv"
        );
        // The same bit on another machine is processor-specific without a name.
        assert_eq!(
            sh_flags_letters(SHF_ALLOC | 0x1000_0000, EM_AARCH64, 0),
            "Ap"
        );
    }

    #[test]
    fn one_p_covers_the_whole_processor_range() {
        // A lower unnamed processor bit hides `E`, as in readelf.
        let f = 0x1000_0000 | SHF_EXCLUDE;
        assert_eq!(sh_flags_letters(f, EM_AARCH64, ELFOSABI_NONE), "p");
        assert_eq!(sh_flags_letters(f, EM_X86_64, ELFOSABI_NONE), "lE");
    }

    #[test]
    fn unknown_generic_bits_are_x() {
        assert_eq!(
            sh_flags_letters(SHF_ALLOC | 0x8, EM_X86_64, ELFOSABI_NONE),
            "Ax"
        );
        assert_eq!(
            sh_flags_letters(0x1000 | 0x2000, EM_X86_64, ELFOSABI_NONE),
            "xx"
        );
    }
}
