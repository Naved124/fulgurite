// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! The ELF file header (`Elf32_Ehdr` / `Elf64_Ehdr`).

use fg_core::{Bitness, ByteView, Field, OutOfBounds};
use serde::Serialize;

/// The identification bytes `e_ident[0..16]` that matter for parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Ident {
    /// `EI_CLASS`: 1 = 32-bit, 2 = 64-bit.
    pub class: Field<u8>,
    /// `EI_DATA`: 1 = little-endian, 2 = big-endian.
    pub data: Field<u8>,
    /// `EI_VERSION`: should be 1.
    pub version: Field<u8>,
    /// `EI_OSABI`.
    pub osabi: Field<u8>,
    /// `EI_ABIVERSION`.
    pub abi_version: Field<u8>,
}

/// The ELF header. Every field keeps its file offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfHeader {
    /// Identification bytes.
    pub ident: Ident,
    /// Object file type (`ET_*`).
    pub e_type: Field<u16>,
    /// Machine (`EM_*`).
    pub e_machine: Field<u16>,
    /// Object file version.
    pub e_version: Field<u32>,
    /// Entry point virtual address.
    pub e_entry: Field<u64>,
    /// File offset of the program header table.
    pub e_phoff: Field<u64>,
    /// File offset of the section header table.
    pub e_shoff: Field<u64>,
    /// Processor-specific flags.
    pub e_flags: Field<u32>,
    /// Size of this header.
    pub e_ehsize: Field<u16>,
    /// Size of one program header entry.
    pub e_phentsize: Field<u16>,
    /// Number of program headers (`PN_XNUM` means "see section header 0").
    pub e_phnum: Field<u16>,
    /// Size of one section header entry.
    pub e_shentsize: Field<u16>,
    /// Number of section headers.
    pub e_shnum: Field<u16>,
    /// Index of the section-name string table.
    pub e_shstrndx: Field<u16>,
}

/// Byte offsets of the header fields that differ between 32- and 64-bit ELF.
struct Layout {
    word: u8,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u64,
    ehsize: u64,
}

const LAYOUT32: Layout = Layout {
    word: 4,
    entry: 24,
    phoff: 28,
    shoff: 32,
    flags: 36,
    ehsize: 40,
};
const LAYOUT64: Layout = Layout {
    word: 8,
    entry: 24,
    phoff: 32,
    shoff: 40,
    flags: 48,
    ehsize: 52,
};

/// Size of the header for a class: 52 bytes (32-bit) or 64 bytes (64-bit).
pub fn header_size(bitness: Bitness) -> u64 {
    match bitness {
        Bitness::Bits32 => 52,
        Bitness::Bits64 => 64,
    }
}

/// Parses the header. `view` must already use the file's byte order.
pub(crate) fn parse(view: &ByteView<'_>, bitness: Bitness) -> Result<ElfHeader, OutOfBounds> {
    use super::consts::*;
    let l = match bitness {
        Bitness::Bits32 => LAYOUT32,
        Bitness::Bits64 => LAYOUT64,
    };
    let word = |off: u64| view.field_uint(off, l.word);
    Ok(ElfHeader {
        ident: Ident {
            class: view.field_u8(EI_CLASS)?,
            data: view.field_u8(EI_DATA)?,
            version: view.field_u8(EI_VERSION)?,
            osabi: view.field_u8(EI_OSABI)?,
            abi_version: view.field_u8(EI_ABIVERSION)?,
        },
        e_type: view.field_u16(16)?,
        e_machine: view.field_u16(18)?,
        e_version: view.field_u32(20)?,
        e_entry: word(l.entry)?,
        e_phoff: word(l.phoff)?,
        e_shoff: word(l.shoff)?,
        e_flags: view.field_u32(l.flags)?,
        e_ehsize: view.field_u16(l.ehsize)?,
        e_phentsize: view.field_u16(l.ehsize + 2)?,
        e_phnum: view.field_u16(l.ehsize + 4)?,
        e_shentsize: view.field_u16(l.ehsize + 6)?,
        e_shnum: view.field_u16(l.ehsize + 8)?,
        e_shstrndx: view.field_u16(l.ehsize + 10)?,
    })
}

/// Reads `sh_info` of section header 0, where the real program-header count
/// lives when `e_phnum == PN_XNUM`.
pub(crate) fn section0_info(
    view: &ByteView<'_>,
    bitness: Bitness,
    shoff: u64,
) -> Result<Field<u32>, OutOfBounds> {
    let at = match bitness {
        Bitness::Bits32 => 28,
        Bitness::Bits64 => 44,
    };
    let off = shoff.checked_add(at).ok_or(OutOfBounds {
        offset: shoff,
        len: at,
        available: view.len(),
    })?;
    view.field_u32(off)
}
