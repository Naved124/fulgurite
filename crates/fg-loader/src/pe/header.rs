// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! DOS header, Rich header, COFF file header and optional header.

use super::consts::*;
use fg_core::{ByteView, Field, OutOfBounds, Span};
use serde::Serialize;

/// The DOS (`MZ`) header. Only `e_magic` and `e_lfanew` matter to Windows; the
/// rest describes the 16-bit DOS stub program and is kept for display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DosHeader {
    /// `MZ`.
    pub e_magic: Field<u16>,
    /// Bytes on the last 512-byte page of the DOS program.
    pub e_cblp: Field<u16>,
    /// Pages in the DOS program.
    pub e_cp: Field<u16>,
    /// DOS relocations.
    pub e_crlc: Field<u16>,
    /// Size of the DOS header in 16-byte paragraphs.
    pub e_cparhdr: Field<u16>,
    /// Minimum extra paragraphs.
    pub e_minalloc: Field<u16>,
    /// Maximum extra paragraphs.
    pub e_maxalloc: Field<u16>,
    /// Initial SS.
    pub e_ss: Field<u16>,
    /// Initial SP.
    pub e_sp: Field<u16>,
    /// Checksum.
    pub e_csum: Field<u16>,
    /// Initial IP.
    pub e_ip: Field<u16>,
    /// Initial CS.
    pub e_cs: Field<u16>,
    /// Offset of the DOS relocation table.
    pub e_lfarlc: Field<u16>,
    /// Overlay number.
    pub e_ovno: Field<u16>,
    /// OEM identifier.
    pub e_oemid: Field<u16>,
    /// OEM information.
    pub e_oeminfo: Field<u16>,
    /// File offset of the NT headers (`PE\0\0`): the only field Windows follows.
    pub e_lfanew: Field<u32>,
}

impl DosHeader {
    /// Reads the 64-byte DOS header.
    pub(crate) fn parse(v: &ByteView<'_>) -> Result<DosHeader, OutOfBounds> {
        let w = |o: u64| v.field_u16(o);
        Ok(DosHeader {
            e_magic: w(0)?,
            e_cblp: w(2)?,
            e_cp: w(4)?,
            e_crlc: w(6)?,
            e_cparhdr: w(8)?,
            e_minalloc: w(10)?,
            e_maxalloc: w(12)?,
            e_ss: w(14)?,
            e_sp: w(16)?,
            e_csum: w(18)?,
            e_ip: w(20)?,
            e_cs: w(22)?,
            e_lfarlc: w(24)?,
            e_ovno: w(26)?,
            e_oemid: w(36)?,
            e_oeminfo: w(38)?,
            e_lfanew: v.field_u32(E_LFANEW_OFFSET)?,
        })
    }
}

/// One `@comp.id` record of the Rich header: which tool built how many objects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RichEntry {
    /// Product (tool) identifier, e.g. the C compiler or the linker of one Visual Studio version.
    pub product: u16,
    /// Tool build number.
    pub build: u16,
    /// Number of objects produced by this tool.
    pub count: u32,
    /// The 8 encoded bytes.
    pub span: Span,
}

/// The undocumented "Rich" header Microsoft's linker writes after the DOS stub:
/// a list of the tools that produced the objects, XOR-encoded with a checksum.
/// It is never used by Windows; it is a toolchain fingerprint and can be forged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RichHeader {
    /// From the encoded `DanS` marker to the end of the key after `Rich`.
    pub span: Span,
    /// XOR key, which is also the checksum the linker computed.
    pub key: Field<u32>,
    /// Decoded records.
    pub entries: Vec<RichEntry>,
    /// Checksum recomputed from the DOS header and the records.
    pub computed_checksum: u32,
}

impl RichHeader {
    /// True if the stored key matches the recomputed checksum (an edited or
    /// transplanted Rich header usually does not).
    pub fn checksum_valid(&self) -> bool {
        self.key.value == self.computed_checksum
    }
}

/// Finds and decodes the Rich header between the DOS header and `e_lfanew`.
pub(crate) fn parse_rich(v: &ByteView<'_>, e_lfanew: u64) -> Option<RichHeader> {
    let end = e_lfanew.min(v.len());
    // "Rich" is followed by the key; scan dword-aligned positions backwards.
    let mut pos = end.checked_sub(8)? & !3;
    let rich_at = loop {
        if pos < DOS_HEADER_SIZE {
            return None;
        }
        if v.u32(pos).ok()? == 0x6863_6952 {
            break pos;
        }
        pos -= 4;
    };
    let key = v.field_u32(rich_at + 4).ok()?;
    let k = key.value;
    // Walk back to the encoded "DanS" (0x536e6144).
    let mut start = rich_at;
    loop {
        if start < DOS_HEADER_SIZE + 4 {
            return None;
        }
        start -= 4;
        if v.u32(start).ok()? ^ k == 0x536e_6144 {
            break;
        }
    }
    // "DanS" is followed by three padding dwords (zero once decoded), then records.
    let mut entries = Vec::new();
    let mut at = start + 16;
    while at + 8 <= rich_at {
        let comp = v.u32(at).ok()? ^ k;
        let count = v.u32(at + 4).ok()? ^ k;
        entries.push(RichEntry {
            product: (comp >> 16) as u16,
            build: comp as u16,
            count,
            span: Span::new(at, 8),
        });
        at += 8;
    }
    // Checksum: the offset of the header, plus every DOS-header byte (except
    // e_lfanew) rotated left by its position, plus each record's id rotated by its count.
    let mut sum = start as u32;
    for i in 0..start {
        if (E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4).contains(&i) {
            continue;
        }
        let b = u32::from(v.u8(i).ok()?);
        sum = sum.wrapping_add(b.rotate_left(i as u32 % 32));
    }
    for e in &entries {
        let comp = (u32::from(e.product) << 16) | u32::from(e.build);
        sum = sum.wrapping_add(comp.rotate_left(e.count % 32));
    }
    Some(RichHeader {
        span: Span::new(start, rich_at + 8 - start),
        key,
        entries,
        computed_checksum: sum,
    })
}

/// The COFF file header that follows `PE\0\0`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FileHeader {
    /// Target machine.
    pub machine: Field<u16>,
    /// Number of section headers.
    pub number_of_sections: Field<u16>,
    /// Link time (seconds since 1970), or a hash in reproducible builds.
    pub time_date_stamp: Field<u32>,
    /// File offset of the COFF symbol table (0 if none).
    pub pointer_to_symbol_table: Field<u32>,
    /// Number of COFF symbol records (including auxiliary records).
    pub number_of_symbols: Field<u32>,
    /// Distance from the start of the optional header to the section table.
    pub size_of_optional_header: Field<u16>,
    /// `IMAGE_FILE_*` flags.
    pub characteristics: Field<u16>,
    /// The header's 20 bytes.
    pub span: Span,
}

impl FileHeader {
    pub(crate) fn parse(v: &ByteView<'_>, at: u64) -> Result<FileHeader, OutOfBounds> {
        Ok(FileHeader {
            machine: v.field_u16(at)?,
            number_of_sections: v.field_u16(at + 2)?,
            time_date_stamp: v.field_u32(at + 4)?,
            pointer_to_symbol_table: v.field_u32(at + 8)?,
            number_of_symbols: v.field_u32(at + 12)?,
            size_of_optional_header: v.field_u16(at + 16)?,
            characteristics: v.field_u16(at + 18)?,
            span: Span::new(at, FILE_HEADER_SIZE),
        })
    }

    /// True if `flag` (`IMAGE_FILE_*`) is set.
    pub fn has(&self, flag: u16) -> bool {
        self.characteristics.value & flag != 0
    }
}

/// One data directory: where a table the loader (or a tool) uses lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DataDirectory {
    /// Index (0 = export ... 15 = reserved).
    pub index: u8,
    /// Address relative to the image base (for the security directory: a file offset).
    pub rva: Field<u32>,
    /// Size in bytes.
    pub size: Field<u32>,
}

impl DataDirectory {
    /// Display name.
    pub fn name(&self) -> &'static str {
        DIRECTORY_NAMES
            .get(usize::from(self.index))
            .copied()
            .unwrap_or("?")
    }

    /// True if the directory is in use (non-zero address).
    pub fn is_present(&self) -> bool {
        self.rva.value != 0
    }
}

/// The optional header (mandatory in images): load address, alignment, sizes,
/// mitigation flags and the data directories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct OptionalHeader {
    /// `0x10b` (PE32) or `0x20b` (PE32+).
    pub magic: Field<u16>,
    /// Linker major version.
    pub major_linker_version: Field<u8>,
    /// Linker minor version.
    pub minor_linker_version: Field<u8>,
    /// Total size of code sections.
    pub size_of_code: Field<u32>,
    /// Total size of initialised data sections.
    pub size_of_initialized_data: Field<u32>,
    /// Total size of zero-filled sections.
    pub size_of_uninitialized_data: Field<u32>,
    /// Entry point, relative to the image base (0 = none, normal for DLLs).
    pub address_of_entry_point: Field<u32>,
    /// Start of code, relative to the image base.
    pub base_of_code: Field<u32>,
    /// Start of data, relative to the image base (PE32 only).
    pub base_of_data: Option<Field<u32>>,
    /// Preferred load address.
    pub image_base: Field<u64>,
    /// Alignment of sections in memory.
    pub section_alignment: Field<u32>,
    /// Alignment of section data in the file.
    pub file_alignment: Field<u32>,
    /// Minimum OS major version.
    pub major_operating_system_version: Field<u16>,
    /// Minimum OS minor version.
    pub minor_operating_system_version: Field<u16>,
    /// Image major version.
    pub major_image_version: Field<u16>,
    /// Image minor version.
    pub minor_image_version: Field<u16>,
    /// Subsystem major version.
    pub major_subsystem_version: Field<u16>,
    /// Subsystem minor version.
    pub minor_subsystem_version: Field<u16>,
    /// Reserved, must be zero.
    pub win32_version_value: Field<u32>,
    /// Size of the image in memory.
    pub size_of_image: Field<u32>,
    /// Size of the headers mapped at the image base.
    pub size_of_headers: Field<u32>,
    /// Image checksum (0 = not set).
    pub checksum: Field<u32>,
    /// Subsystem (console, GUI, native, EFI...).
    pub subsystem: Field<u16>,
    /// `IMAGE_DLLCHARACTERISTICS_*` flags: ASLR, DEP, CFG...
    pub dll_characteristics: Field<u16>,
    /// Stack reserve size.
    pub size_of_stack_reserve: Field<u64>,
    /// Stack commit size.
    pub size_of_stack_commit: Field<u64>,
    /// Heap reserve size.
    pub size_of_heap_reserve: Field<u64>,
    /// Heap commit size.
    pub size_of_heap_commit: Field<u64>,
    /// Reserved, must be zero.
    pub loader_flags: Field<u32>,
    /// Number of data directories declared (the loader uses at most 16).
    pub number_of_rva_and_sizes: Field<u32>,
    /// The data directories that were read (at most 16).
    pub data_directories: Vec<DataDirectory>,
    /// File offset of the optional header.
    pub offset: u64,
}

impl OptionalHeader {
    /// True for PE32+ (64-bit).
    pub fn is_pe32_plus(&self) -> bool {
        self.magic.value == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    /// True if `flag` (`IMAGE_DLLCHARACTERISTICS_*`) is set.
    pub fn has(&self, flag: u16) -> bool {
        self.dll_characteristics.value & flag != 0
    }

    /// Data directory `index`, if declared and present.
    pub fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories
            .get(index)
            .filter(|d| d.is_present() || d.size.value != 0)
    }

    /// Size of the fixed part (before the data directories).
    pub fn fixed_size(pe32_plus: bool) -> u64 {
        if pe32_plus { 112 } else { 96 }
    }

    /// Reads the optional header at `at`. Fails only if the fixed part is cut off
    /// by the end of the file; missing directories are simply not returned.
    pub(crate) fn parse(v: &ByteView<'_>, at: u64) -> Result<OptionalHeader, OutOfBounds> {
        let magic = v.field_u16(at)?;
        let plus = magic.value == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        let w = |o: u64| v.field_u16(at + o);
        let d = |o: u64| v.field_u32(at + o);
        // Fields that are pointer-sized in PE32+.
        let p = |o32: u64, o64: u64| -> Result<Field<u64>, OutOfBounds> {
            if plus {
                v.field_u64(at + o64)
            } else {
                Ok(v.field_u32(at + o32)?.map(u64::from))
            }
        };
        // Same offsets in both layouts until base_of_data.
        let fixed = Self::fixed_size(plus);
        if !v.contains(at, fixed) {
            // Report the precise read that fails.
            v.bytes(at, fixed)?;
        }
        let number_of_rva_and_sizes = d(if plus { 108 } else { 92 })?;
        let mut data_directories = Vec::new();
        let n = number_of_rva_and_sizes
            .value
            .min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for i in 0..n {
            let o = at + fixed + u64::from(i) * 8;
            let (Ok(rva), Ok(size)) = (v.field_u32(o), v.field_u32(o + 4)) else {
                break;
            };
            data_directories.push(DataDirectory {
                index: i as u8,
                rva,
                size,
            });
        }
        Ok(OptionalHeader {
            magic,
            major_linker_version: v.field_u8(at + 2)?,
            minor_linker_version: v.field_u8(at + 3)?,
            size_of_code: d(4)?,
            size_of_initialized_data: d(8)?,
            size_of_uninitialized_data: d(12)?,
            address_of_entry_point: d(16)?,
            base_of_code: d(20)?,
            base_of_data: if plus { None } else { Some(d(24)?) },
            image_base: p(28, 24)?,
            section_alignment: d(32)?,
            file_alignment: d(36)?,
            major_operating_system_version: w(40)?,
            minor_operating_system_version: w(42)?,
            major_image_version: w(44)?,
            minor_image_version: w(46)?,
            major_subsystem_version: w(48)?,
            minor_subsystem_version: w(50)?,
            win32_version_value: d(52)?,
            size_of_image: d(56)?,
            size_of_headers: d(60)?,
            checksum: d(64)?,
            subsystem: w(68)?,
            dll_characteristics: w(70)?,
            size_of_stack_reserve: p(72, 72)?,
            size_of_stack_commit: p(76, 80)?,
            size_of_heap_reserve: p(80, 88)?,
            size_of_heap_commit: p(84, 96)?,
            loader_flags: d(if plus { 104 } else { 88 })?,
            number_of_rva_and_sizes,
            data_directories,
            offset: at,
        })
    }
}
