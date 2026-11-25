// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Section headers (`Elf32_Shdr` / `Elf64_Shdr`).
//!
//! Sections are metadata for linkers and debuggers; the OS loader ignores them.
//! They can be stripped or forged, so everything here is advisory and is checked
//! against the program headers (the loader's truth).

use super::consts::*;
use super::header::ElfHeader;
use super::phdr::ProgramHeader;
use super::strtab::StringTable;
use fg_core::{Anomaly, Bitness, ByteView, Field, OutOfBounds, Severity, Span};
use serde::Serialize;

/// One section header. Every field keeps its file offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SectionHeader {
    /// Position in the section header table.
    pub index: u32,
    /// The whole entry's bytes.
    pub span: Span,
    /// Offset of the name in the section-name string table.
    pub sh_name: Field<u32>,
    /// The resolved name, if it could be read.
    pub name: Option<Field<String>>,
    /// Section type (`SHT_*`).
    pub sh_type: Field<u32>,
    /// Flags (`SHF_*`).
    pub sh_flags: Field<u64>,
    /// Address in memory (0 if not loaded).
    pub sh_addr: Field<u64>,
    /// File offset of the section's bytes.
    pub sh_offset: Field<u64>,
    /// Size in bytes.
    pub sh_size: Field<u64>,
    /// Type-specific link to another section.
    pub sh_link: Field<u32>,
    /// Type-specific extra information.
    pub sh_info: Field<u32>,
    /// Alignment.
    pub sh_addralign: Field<u64>,
    /// Entry size for tables (0 otherwise).
    pub sh_entsize: Field<u64>,
}

impl SectionHeader {
    /// Name, or `""` if it could not be read.
    pub fn name_str(&self) -> &str {
        self.name.as_ref().map_or("", |n| n.value.as_str())
    }

    /// True if the section is loaded into memory at run time.
    pub fn is_alloc(&self) -> bool {
        self.sh_flags.value & SHF_ALLOC != 0
    }

    /// True if the section occupies no file bytes (e.g. `.bss`).
    pub fn is_nobits(&self) -> bool {
        self.sh_type.value == SHT_NOBITS
    }

    /// Bytes of the file the section occupies (empty for `SHT_NOBITS`).
    pub fn file_range(&self) -> Span {
        Span::new(
            self.sh_offset.value,
            if self.is_nobits() {
                0
            } else {
                self.sh_size.value
            },
        )
    }
}

/// Size of one entry: 40 bytes (32-bit) or 64 bytes (64-bit).
pub fn entry_size(bitness: Bitness) -> u64 {
    match bitness {
        Bitness::Bits32 => 40,
        Bitness::Bits64 => 64,
    }
}

fn parse_one(
    view: &ByteView<'_>,
    bitness: Bitness,
    index: u32,
    base: u64,
) -> Result<SectionHeader, OutOfBounds> {
    let oob = OutOfBounds {
        offset: base,
        len: entry_size(bitness),
        available: view.len(),
    };
    if !view.contains(base, entry_size(bitness)) {
        return Err(oob);
    }
    let w = bitness.word_size();
    let (flags, addr, offset, size, link, info, align, entsize) = match bitness {
        Bitness::Bits64 => (8, 16, 24, 32, 40, 44, 48, 56),
        Bitness::Bits32 => (8, 12, 16, 20, 24, 28, 32, 36),
    };
    Ok(SectionHeader {
        index,
        span: Span::new(base, entry_size(bitness)),
        sh_name: view.field_u32(base)?,
        name: None,
        sh_type: view.field_u32(base + 4)?,
        sh_flags: view.field_uint(base + flags, w)?,
        sh_addr: view.field_uint(base + addr, w)?,
        sh_offset: view.field_uint(base + offset, w)?,
        sh_size: view.field_uint(base + size, w)?,
        sh_link: view.field_u32(base + link)?,
        sh_info: view.field_u32(base + info)?,
        sh_addralign: view.field_uint(base + align, w)?,
        sh_entsize: view.field_uint(base + entsize, w)?,
    })
}

/// Result of reading the section header table.
pub(crate) struct SectionScan {
    pub headers: Vec<SectionHeader>,
    /// Real count (differs from `e_shnum` when the escape is used).
    pub count: u64,
    /// Real index of the section-name table, if valid.
    pub shstrndx: Option<u32>,
}

/// Reads the section header table, resolving the `e_shnum == 0` and
/// `e_shstrndx == SHN_XINDEX` escapes and the section names.
pub(crate) fn read_table(
    view: &ByteView<'_>,
    bitness: Bitness,
    h: &ElfHeader,
    limit: u32,
    max_name_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> SectionScan {
    let empty = SectionScan {
        headers: Vec::new(),
        count: 0,
        shstrndx: None,
    };
    let shoff = h.e_shoff.value;
    if shoff == 0 {
        if h.e_shnum.value != 0 {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.section.no_table",
                    format!(
                        "e_shnum is {} but e_shoff is 0, so there is no section header table",
                        h.e_shnum.value
                    ),
                )
                .at(h.e_shoff.span),
            );
        }
        return empty;
    }

    let expected = entry_size(bitness);
    let stride = u64::from(h.e_shentsize.value);
    if stride < expected {
        anomalies.push(
            Anomaly::new(Severity::Error, "elf.section.entsize_too_small",
                format!("e_shentsize is {stride}, smaller than the {expected}-byte entry; sections not read"))
            .at(h.e_shentsize.span),
        );
        return empty;
    }
    if stride != expected {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.section.entsize",
                format!(
                    "e_shentsize is {stride}, expected {expected}; reading with the declared stride"
                ),
            )
            .at(h.e_shentsize.span),
        );
    }

    // Section header 0 holds the real count / name-table index when the header
    // fields cannot (more than 0xff00 sections).
    let first = parse_one(view, bitness, 0, shoff).ok();
    let mut count = u64::from(h.e_shnum.value);
    if count == 0 {
        match &first {
            Some(s0) if s0.sh_size.value != 0 => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Info,
                        "elf.section.extended_count",
                        format!(
                            "e_shnum is 0; the real count {} comes from section header 0",
                            s0.sh_size.value
                        ),
                    )
                    .at(s0.sh_size.span),
                );
                count = s0.sh_size.value;
            }
            Some(_) => return empty, // genuinely no sections
            None => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Error,
                        "elf.section.table_truncated",
                        "section header table starts outside the file",
                    )
                    .at(h.e_shoff.span),
                );
                return empty;
            }
        }
    }
    let mut shstrndx = u64::from(h.e_shstrndx.value);
    if h.e_shstrndx.value == SHN_XINDEX
        && let Some(s0) = &first
    {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "elf.section.extended_shstrndx",
                format!(
                    "e_shstrndx is SHN_XINDEX; the real index {} comes from section header 0",
                    s0.sh_link.value
                ),
            )
            .at(s0.sh_link.span),
        );
        shstrndx = u64::from(s0.sh_link.value);
    }

    let mut n = count;
    if n > u64::from(limit) {
        anomalies.push(
            Anomaly::new(
                Severity::Error,
                "elf.section.limit",
                format!(
                    "{n} section headers exceeds the limit of {limit}; reading the first {limit}"
                ),
            )
            .at(h.e_shnum.span),
        );
        n = u64::from(limit);
    }
    let table = Span::new(shoff, n.saturating_mul(stride));
    if table.end().is_none() {
        anomalies.push(
            Anomaly::new(
                Severity::Error,
                "elf.section.table_overflow",
                "e_shoff + table size overflows a 64-bit offset",
            )
            .at(h.e_shoff.span),
        );
        return empty;
    }

    let mut headers = Vec::new();
    for i in 0..n {
        match parse_one(view, bitness, i as u32, shoff + i * stride) {
            Ok(s) => headers.push(s),
            Err(_) => {
                anomalies.push(
                    Anomaly::new(Severity::Error, "elf.section.table_truncated",
                        format!("section header table claims {count} entries but the file ends after {i}"))
                    .at(table),
                );
                break;
            }
        }
    }

    // Names.
    let names = if shstrndx == u64::from(SHN_UNDEF) {
        None
    } else if let Some(t) = headers.get(shstrndx as usize) {
        if t.sh_type.value != SHT_STRTAB {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.section.shstrtab_type",
                    format!(
                        "section-name table #{shstrndx} has type {:#x}, not STRTAB",
                        t.sh_type.value
                    ),
                )
                .at(t.sh_type.span),
            );
        }
        Some(StringTable::new(*view, t.file_range(), max_name_len))
    } else {
        anomalies.push(
            Anomaly::new(Severity::Warning, "elf.section.shstrndx_invalid",
                format!("e_shstrndx {shstrndx} is not a valid section index ({} sections); names unavailable",
                    headers.len()))
            .at(h.e_shstrndx.span),
        );
        None
    };
    let mut bad_names = 0u32;
    if let Some(names) = names {
        for s in &mut headers {
            s.name = names.get(s.sh_name.value);
            if s.name.is_none() {
                bad_names += 1;
            }
        }
    }
    if bad_names > 0 {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "elf.section.name_invalid",
            format!("{bad_names} section name(s) point outside the section-name table"),
        ));
    }

    let shstrndx = (shstrndx < headers.len() as u64 && shstrndx != 0).then_some(shstrndx as u32);
    SectionScan {
        headers,
        count,
        shstrndx,
    }
}

/// Checks sections (metadata claims) against segments (what the OS maps).
pub(crate) fn check_against_segments(
    sections: &[SectionHeader],
    phdrs: &[ProgramHeader],
    file_len: u64,
    anomalies: &mut Vec<Anomaly>,
) {
    let loads: Vec<&ProgramHeader> = phdrs.iter().filter(|p| p.p_type.value == PT_LOAD).collect();
    for s in sections {
        let label = format!("section #{} {}", s.index, s.name_str());
        let range = s.file_range();
        if s.sh_type.value != SHT_NULL
            && range.len > 0
            && range.end().is_none_or(|e| e.0 > file_len)
        {
            anomalies.push(
                Anomaly::new(Severity::Warning, "elf.section.past_eof",
                    format!("{label} claims file bytes {:#x}..+{:#x}, past the end of the file ({file_len} bytes)",
                        range.offset.0, range.len))
                .at(s.span),
            );
        }
        // Only loaded sections with real bytes can be compared with segments.
        // TLS sections live in the TLS template, not at their address.
        if !s.is_alloc()
            || s.is_nobits()
            || s.sh_size.value == 0
            || loads.is_empty()
            || s.sh_flags.value & SHF_TLS != 0
        {
            continue;
        }
        let addr = s.sh_addr.value;
        let Some(seg) = loads
            .iter()
            .find(|p| addr >= p.p_vaddr.value && addr - p.p_vaddr.value < p.p_memsz.value)
        else {
            anomalies.push(
                Anomaly::new(Severity::Warning, "elf.section.outside_segments",
                    format!("{label} claims address {addr:#x}, which no LOAD segment maps"))
                .at(s.sh_addr.span)
                .os("the OS ignores section headers, so these bytes are not where the metadata says"),
            );
            continue;
        };
        let expected_off = seg.p_offset.value.wrapping_add(addr - seg.p_vaddr.value);
        if expected_off != s.sh_offset.value {
            anomalies.push(
                Anomaly::new(Severity::Warning, "elf.section.offset_mismatch",
                    format!("{label}: sh_offset {:#x} but LOAD #{} maps address {addr:#x} from offset {expected_off:#x}",
                        s.sh_offset.value, seg.index))
                .at(s.sh_offset.span)
                .os("the OS uses the segment, so the real bytes are at the segment's offset"),
            );
        }
        if s.sh_flags.value & SHF_EXECINSTR != 0 && !seg.perms().execute {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.section.exec_mismatch",
                    format!(
                        "{label} claims to be executable but LOAD #{} is {}",
                        seg.index,
                        seg.perms()
                    ),
                )
                .at(s.sh_flags.span)
                .os("the OS applies the segment's permissions, so this code cannot run in place"),
            );
        }
    }
}
