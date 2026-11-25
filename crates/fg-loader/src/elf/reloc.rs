// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Relocation tables: `REL`, `RELA` and packed `RELR`.
//!
//! In loaded files (executables, shared objects) the tables are found the way
//! the dynamic linker finds them: through the dynamic segment (`DT_RELA`,
//! `DT_REL`, `DT_JMPREL`, `DT_RELR`). Section headers only supply names, and any
//! relocation section the dynamic segment does not cover (object files, static
//! executables, `--emit-relocs`) is read through its section header.

use super::consts::*;
use super::dynamic::DynamicEntry;
use super::phdr::{LoadMap, ProgramHeader, map_va};
use super::section::SectionHeader;
use crate::model::{Limits, RelocKind, SymbolTable};
use fg_core::{Anomaly, Bitness, ByteView, Field, Severity, Span};
use serde::Serialize;

/// Encoding of a relocation table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum RelocFormat {
    /// `r_offset, r_info`; the addend is the value stored at the location.
    Rel,
    /// `r_offset, r_info, r_addend`.
    Rela,
    /// Packed relative relocations: addresses and bitmaps, no symbols or types.
    Relr,
}

/// Where a relocation table was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum RelocSource {
    /// Through the dynamic segment, by the tag holding its address.
    Dynamic(i64),
    /// Through a section header (index given).
    Section(u32),
}

/// One relocation entry. Every field keeps its file offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfRelocation {
    /// Position in the table (for `RELR`: in the decoded list).
    pub index: u32,
    /// The entry's bytes (for `RELR`: the encoded word that produced it).
    pub span: Span,
    /// Location to patch (decoded for `RELR`).
    pub r_offset: Field<u64>,
    /// Symbol index and type, packed (`None` for `RELR`).
    pub r_info: Option<Field<u64>>,
    /// Explicit addend (`RELA` only).
    pub r_addend: Option<Field<i64>>,
    /// Type, unpacked from `r_info` (the machine's relative type for `RELR`).
    pub r_type: u32,
    /// Symbol index, unpacked from `r_info` (0 = no symbol).
    pub r_sym: u32,
    /// The pointer-sized value stored at the location, if file-backed.
    pub stored: Option<Field<u64>>,
}

/// One relocation table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfRelocTable {
    /// Section name when a section header describes exactly this table,
    /// otherwise the dynamic tag (`DT_RELA`, `DT_JMPREL` ...).
    pub name: String,
    /// Encoding.
    pub format: RelocFormat,
    /// How the table was found.
    pub source: RelocSource,
    /// Section header describing the table, if any.
    pub section: Option<u32>,
    /// The table's bytes.
    pub file_range: Span,
    /// Symbol table its symbol indexes refer to.
    pub symbols: Option<SymbolTable>,
    /// Section the relocations patch (object files: `sh_info`).
    pub applies_to: Option<u32>,
    /// Encoded words (`RELR` only; `entries` holds the decoded relocations).
    pub relr_words: u64,
    /// Applied when the program starts: by the dynamic linker (tables in the
    /// dynamic segment), or by the C library's startup code (`IRELATIVE` tables of
    /// static executables). Link-time tables (object files, `--emit-relocs`) are not.
    pub applied_at_load: bool,
    /// Entries in table order.
    pub entries: Vec<ElfRelocation>,
}

/// Relocation kind for a machine's type number.
pub fn kind_of(machine: u16, r_type: u32) -> RelocKind {
    use RelocKind::*;
    match (machine, r_type) {
        (EM_X86_64, 0) | (EM_386, 0) | (EM_AARCH64, 0 | 256) | (EM_ARM, 0) | (EM_RISCV, 0) => None,
        (EM_X86_64, 8 | 38) | (EM_386, 8) | (EM_AARCH64, 1027) | (EM_ARM, 23) | (EM_RISCV, 3) => {
            Relative
        }
        (EM_X86_64, 1) | (EM_386, 1) | (EM_AARCH64, 257) | (EM_ARM, 2) | (EM_RISCV, 1 | 2) => {
            Absolute
        }
        (EM_X86_64, 6) | (EM_386, 6) | (EM_AARCH64, 1025) | (EM_ARM, 21) => GotEntry,
        (EM_X86_64, 7) | (EM_386, 7) | (EM_AARCH64, 1026) | (EM_ARM, 22) | (EM_RISCV, 5) => PltSlot,
        (EM_X86_64, 5) | (EM_386, 5) | (EM_AARCH64, 1024) | (EM_ARM, 20) | (EM_RISCV, 4) => Copy,
        (EM_X86_64, 37) | (EM_386, 42) | (EM_AARCH64, 1032) | (EM_ARM, 160) | (EM_RISCV, 58) => {
            IndirectRelative
        }
        (EM_X86_64, 16 | 17 | 18 | 36)
        | (EM_386, 14 | 35 | 36 | 37 | 41)
        | (EM_AARCH64, 1028..=1031)
        | (EM_ARM, 13 | 17 | 18 | 19)
        | (EM_RISCV, 6..=12) => Tls,
        _ => Other,
    }
}

/// The machine's relative relocation type (what each `RELR` location means).
fn relative_type(machine: u16) -> u32 {
    match machine {
        EM_X86_64 | EM_386 => 8,
        EM_AARCH64 => 1027,
        EM_ARM => 23,
        EM_RISCV => 3,
        _ => 0,
    }
}

/// `REL` or `RELA` for `DT_JMPREL` when `DT_PLTREL` is missing: the psABI default.
fn default_plt_format(machine: u16) -> RelocFormat {
    match machine {
        EM_386 | EM_ARM => RelocFormat::Rel,
        _ => RelocFormat::Rela,
    }
}

fn entry_size(format: RelocFormat, bitness: Bitness) -> u64 {
    let w = u64::from(bitness.word_size());
    match format {
        RelocFormat::Rel => 2 * w,
        RelocFormat::Rela => 3 * w,
        RelocFormat::Relr => w,
    }
}

fn format_name(f: RelocFormat) -> &'static str {
    match f {
        RelocFormat::Rel => "REL",
        RelocFormat::Rela => "RELA",
        RelocFormat::Relr => "RELR",
    }
}

/// Everything the reader needs about the file.
pub(crate) struct Ctx<'a, 'b> {
    pub view: &'b ByteView<'a>,
    pub bitness: Bitness,
    pub machine: u16,
    pub relocatable: bool,
    pub phdrs: &'b [ProgramHeader],
    /// `phdrs`' load segments, for looking up many addresses.
    pub load_map: &'b LoadMap,
    pub sections: &'b [SectionHeader],
    pub dynamic: &'b [DynamicEntry],
    pub dynsym_len: Option<usize>,
    pub symtab_len: Option<usize>,
    pub limits: &'b Limits,
}

/// A table location before it is read.
struct Pending {
    name: String,
    format: RelocFormat,
    source: RelocSource,
    section: Option<u32>,
    offset: u64,
    size: u64,
    symbols: Option<SymbolTable>,
    applies_to: Option<u32>,
    applied_at_load: bool,
}

/// Reads every relocation table.
pub(crate) fn read_all(ctx: &Ctx<'_, '_>, anomalies: &mut Vec<Anomaly>) -> Vec<ElfRelocTable> {
    let mut pending = dynamic_tables(ctx, anomalies);
    name_from_sections(ctx, &mut pending, anomalies);
    let mut left = u64::from(ctx.limits.max_total_relocations);
    let mut out = Vec::new();
    for p in pending {
        if left == 0 {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "elf.reloc.total_limit",
                format!(
                    "the file's relocation tables hold more than {} relocations in all; table {} and those after it are not read",
                    ctx.limits.max_total_relocations, p.name
                ),
            ));
            break;
        }
        let limit = u64::from(ctx.limits.max_relocations).min(left);
        let t = read_table(ctx, p, limit, anomalies);
        left -= (t.entries.len() as u64).min(left);
        out.push(t);
    }
    out
}

fn dyn_entry(dynamic: &[DynamicEntry], tag: i64) -> Option<&DynamicEntry> {
    dynamic.iter().find(|d| d.tag.value == tag)
}

fn dynamic_tables(ctx: &Ctx<'_, '_>, anomalies: &mut Vec<Anomaly>) -> Vec<Pending> {
    let d = ctx.dynamic;
    let plt_format = match dyn_entry(d, DT_PLTREL) {
        None => default_plt_format(ctx.machine),
        Some(e) if e.value.value == DT_RELA as u64 => RelocFormat::Rela,
        Some(e) if e.value.value == DT_REL as u64 => RelocFormat::Rel,
        Some(e) => {
            let f = default_plt_format(ctx.machine);
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.reloc.pltrel_invalid",
                    format!(
                        "DT_PLTREL is {}, neither DT_RELA (7) nor DT_REL (17); assuming {}",
                        e.value.value,
                        format_name(f)
                    ),
                )
                .at(e.value.span),
            );
            f
        }
    };
    let specs = [
        (
            "DT_RELA",
            DT_RELA,
            DT_RELASZ,
            Some(DT_RELAENT),
            RelocFormat::Rela,
        ),
        (
            "DT_REL",
            DT_REL,
            DT_RELSZ,
            Some(DT_RELENT),
            RelocFormat::Rel,
        ),
        ("DT_JMPREL", DT_JMPREL, DT_PLTRELSZ, None, plt_format),
        (
            "DT_RELR",
            DT_RELR,
            DT_RELRSZ,
            Some(DT_RELRENT),
            RelocFormat::Relr,
        ),
    ];
    let mut out: Vec<Pending> = Vec::new();
    for (name, addr_tag, size_tag, ent_tag, format) in specs {
        let Some(addr) = dyn_entry(d, addr_tag) else {
            continue;
        };
        let size = dyn_entry(d, size_tag).map_or(0, |e| e.value.value);
        if size == 0 {
            continue;
        }
        let expected = entry_size(format, ctx.bitness);
        if let Some(ent) = ent_tag.and_then(|t| dyn_entry(d, t))
            && ent.value.value != expected
        {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.reloc.entsize",
                    format!(
                        "{name}: entry size is {}, expected {expected}; using {expected}",
                        ent.value.value
                    ),
                )
                .at(ent.value.span),
            );
        }
        let Some(offset) = map_va(ctx.phdrs, name, addr, anomalies) else {
            continue;
        };
        out.push(Pending {
            name: name.to_string(),
            format,
            source: RelocSource::Dynamic(addr_tag),
            section: None,
            offset,
            size,
            symbols: Some(SymbolTable::Dynamic),
            applies_to: None,
            applied_at_load: true,
        });
    }
    // Linkers may make DT_RELASZ include the PLT relocations that follow it; the
    // dynamic linker then skips them in the first pass. Do the same.
    if let Some(j) = out.iter().position(|p| p.name == "DT_JMPREL") {
        let (jo, js, jf) = (out[j].offset, out[j].size, out[j].format);
        for (i, p) in out.iter_mut().enumerate() {
            if i == j || p.format != jf {
                continue;
            }
            let end = p.offset.saturating_add(p.size);
            if p.offset <= jo && jo.saturating_add(js) == end {
                p.size -= js;
            } else if p.offset < jo.saturating_add(js) && jo < end {
                anomalies.push(Anomaly::new(
                    Severity::Warning,
                    "elf.reloc.overlap",
                    format!(
                        "{} and DT_JMPREL overlap: some relocations would be applied twice",
                        p.name
                    ),
                ));
            }
        }
        out.retain(|p| p.size > 0);
    }
    out
}

/// Gives dynamic tables their section names and adds the relocation sections
/// the dynamic segment does not cover.
fn name_from_sections(ctx: &Ctx<'_, '_>, pending: &mut Vec<Pending>, anomalies: &mut Vec<Anomaly>) {
    let has_dynamic = !ctx.dynamic.is_empty();
    let dynamic_ranges: Vec<(u64, u64)> = pending
        .iter()
        .map(|p| (p.offset, p.offset.saturating_add(p.size)))
        .collect();
    for s in ctx.sections {
        let format = match s.sh_type.value {
            SHT_RELA => RelocFormat::Rela,
            SHT_REL => RelocFormat::Rel,
            SHT_RELR => RelocFormat::Relr,
            _ => continue,
        };
        let range = s.file_range();
        if range.len == 0 {
            continue;
        }
        let (start, end) = (range.offset.0, range.offset.0.saturating_add(range.len));
        if let Some(p) = pending
            .iter_mut()
            .find(|p| p.offset == start && p.size == range.len && p.format == format)
        {
            p.name = s.name_str().to_string();
            p.section = Some(s.index);
            continue;
        }
        if dynamic_ranges.iter().any(|&(a, b)| a <= start && end <= b) {
            continue; // part of a table already read through the dynamic segment
        }
        if has_dynamic && s.is_alloc() {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "elf.reloc.section_unused",
                    format!(
                        "relocation section #{} {} is not referenced by the dynamic segment; \
                         the dynamic linker never applies it",
                        s.index,
                        s.name_str()
                    ),
                )
                .at(s.span),
            );
        }
        let symbols = match ctx.sections.get(s.sh_link.value as usize) {
            _ if format == RelocFormat::Relr || s.sh_link.value == 0 => None,
            Some(l) if l.sh_type.value == SHT_DYNSYM => Some(SymbolTable::Dynamic),
            Some(l) if l.sh_type.value == SHT_SYMTAB => Some(SymbolTable::Static),
            _ => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "elf.reloc.symtab_invalid",
                        format!(
                            "relocation section #{} {}: sh_link {} is not a symbol table",
                            s.index,
                            s.name_str(),
                            s.sh_link.value
                        ),
                    )
                    .at(s.sh_link.span),
                );
                None
            }
        };
        let applies_to = (s.sh_flags.value & SHF_INFO_LINK != 0 || ctx.relocatable)
            .then_some(s.sh_info.value)
            .filter(|&i| i != 0);
        if let Some(t) = applies_to
            && ctx.sections.get(t as usize).is_none()
        {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.reloc.target_invalid",
                    format!(
                        "relocation section #{} {}: sh_info {t} is not a section",
                        s.index,
                        s.name_str()
                    ),
                )
                .at(s.sh_info.span),
            );
        }
        pending.push(Pending {
            name: s.name_str().to_string(),
            format,
            source: RelocSource::Section(s.index),
            section: Some(s.index),
            offset: start,
            size: range.len,
            symbols,
            applies_to,
            applied_at_load: !has_dynamic && !ctx.relocatable && s.is_alloc(),
        });
    }
}

/// File offset of the location a relocation patches.
fn place_offset(ctx: &Ctx<'_, '_>, applies_to: Option<u32>, r_offset: u64) -> Option<u64> {
    if ctx.relocatable {
        let s = ctx.sections.get(applies_to? as usize)?;
        let range = s.file_range();
        return (r_offset < range.len)
            .then(|| range.offset.0.checked_add(r_offset))
            .flatten();
    }
    ctx.load_map.offset(r_offset)
}

/// Reads one table, at most `limit` relocations of it.
fn read_table(
    ctx: &Ctx<'_, '_>,
    p: Pending,
    limit: u64,
    anomalies: &mut Vec<Anomaly>,
) -> ElfRelocTable {
    let view = ctx.view;
    let w = ctx.bitness.word_size();
    let ent = entry_size(p.format, ctx.bitness);
    let mut size = p.size;
    if !view.contains(p.offset, size) {
        let available = view.len().saturating_sub(p.offset);
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.reloc.truncated",
                format!(
                    "relocation table {} claims {size:#x} bytes at {:#x} but the file ends after {available:#x}",
                    p.name, p.offset
                ),
            )
            .at(Span::new(p.offset, available)),
        );
        size = available;
    }
    if !size.is_multiple_of(ent) {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "elf.reloc.size",
            format!(
                "relocation table {} is {size:#x} bytes, not a multiple of the {ent}-byte entry",
                p.name
            ),
        ));
    }
    let count = size / ent;
    let mut table = ElfRelocTable {
        name: p.name.clone(),
        format: p.format,
        source: p.source,
        section: p.section,
        file_range: Span::new(p.offset, size),
        symbols: p.symbols,
        applies_to: p.applies_to,
        relr_words: 0,
        applied_at_load: p.applied_at_load,
        entries: Vec::new(),
    };
    // In object files with explicit addends the bytes at the location are just
    // instruction or data bytes of varying width, so they are not recorded.
    let record_stored = !(ctx.relocatable && p.format == RelocFormat::Rela);
    let stored = |r_offset: u64| {
        record_stored
            .then(|| place_offset(ctx, p.applies_to, r_offset))
            .flatten()
            .and_then(|o| view.field_uint(o, w).ok())
    };
    let mut hit_limit = false;

    if p.format == RelocFormat::Relr {
        table.relr_words = count;
        let bits = u64::from(w) * 8;
        let wb = u64::from(w);
        let mut next: Option<u64> = None;
        let mut bad_start = false;
        'words: for i in 0..count {
            let Some(at) = i.checked_mul(ent).and_then(|d| p.offset.checked_add(d)) else {
                break;
            };
            let Ok(word) = view.field_uint(at, w) else {
                break;
            };
            let emit = |addr: u64, table: &mut ElfRelocTable| -> bool {
                if table.entries.len() as u64 >= limit {
                    return false;
                }
                table.entries.push(ElfRelocation {
                    index: table.entries.len() as u32,
                    span: word.span,
                    r_offset: Field::new(addr, word.span),
                    r_info: None,
                    r_addend: None,
                    r_type: relative_type(ctx.machine),
                    r_sym: 0,
                    stored: stored(addr),
                });
                true
            };
            if word.value & 1 == 0 {
                if !emit(word.value, &mut table) {
                    hit_limit = true;
                    break;
                }
                next = word.value.checked_add(wb);
            } else {
                let Some(base) = next else {
                    bad_start = true;
                    continue;
                };
                for bit in 1..bits {
                    if (word.value >> bit) & 1 == 1 {
                        let Some(addr) =
                            (bit - 1).checked_mul(wb).and_then(|d| base.checked_add(d))
                        else {
                            break 'words;
                        };
                        if !emit(addr, &mut table) {
                            hit_limit = true;
                            break 'words;
                        }
                    }
                }
                next = (bits - 1).checked_mul(wb).and_then(|d| base.checked_add(d));
            }
        }
        if bad_start {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.relr.no_base",
                    format!(
                        "RELR table {} has a bitmap word before any address word; those bits were ignored",
                        p.name
                    ),
                )
                .at(table.file_range),
            );
        }
    } else {
        for i in 0..count {
            if i >= limit {
                hit_limit = true;
                break;
            }
            // Offsets come from the file and can sit just below 2^64.
            let field = |k: u64| {
                i.checked_mul(ent)
                    .and_then(|d| p.offset.checked_add(d))
                    .and_then(|at| at.checked_add(k * u64::from(w)))
            };
            let (Some(at), Some(info_at), Some(addend_at)) = (field(0), field(1), field(2)) else {
                break;
            };
            let (Ok(off), Ok(info)) = (view.field_uint(at, w), view.field_uint(info_at, w)) else {
                break;
            };
            let addend = if p.format == RelocFormat::Rela {
                match view.field_uint(addend_at, w) {
                    Ok(a) => Some(a.map(|v| match ctx.bitness {
                        Bitness::Bits32 => i64::from(v as u32 as i32),
                        Bitness::Bits64 => v as i64,
                    })),
                    Err(_) => break,
                }
            } else {
                None
            };
            let (r_sym, r_type) = match ctx.bitness {
                Bitness::Bits64 => ((info.value >> 32) as u32, info.value as u32),
                Bitness::Bits32 => ((info.value >> 8) as u32, (info.value & 0xff) as u32),
            };
            table.entries.push(ElfRelocation {
                index: i as u32,
                span: Span::new(at, ent),
                stored: stored(off.value),
                r_offset: off,
                r_info: Some(info),
                r_addend: addend,
                r_type,
                r_sym,
            });
        }
    }
    if hit_limit {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.reloc.limit",
                format!(
                    "relocation table {} has more than {limit} relocations; stopped reading",
                    p.name
                ),
            )
            .at(table.file_range),
        );
    }
    check_table(ctx, &table, anomalies);
    table
}

/// Symbol indexes, places and text relocations.
fn check_table(ctx: &Ctx<'_, '_>, t: &ElfRelocTable, anomalies: &mut Vec<Anomaly>) {
    let sym_len = match t.symbols {
        Some(SymbolTable::Dynamic) => ctx.dynsym_len,
        Some(SymbolTable::Static) => ctx.symtab_len,
        _ => None,
    };
    let bad_sym: Vec<&ElfRelocation> = t
        .entries
        .iter()
        .filter(|r| r.r_sym != 0 && sym_len.is_none_or(|n| r.r_sym as usize >= n))
        .collect();
    if let Some(first) = bad_sym.first() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.reloc.bad_symbol",
                format!(
                    "{}: {} relocation(s) name a symbol outside the symbol table (first: #{} uses symbol {})",
                    t.name,
                    bad_sym.len(),
                    first.index,
                    first.r_sym
                ),
            )
            .at(first.span),
        );
    }
    let unknown = t
        .entries
        .iter()
        .filter(|r| r_type_name(ctx.machine, r.r_type).is_none())
        .count();
    if unknown > 0 && r_type_name(ctx.machine, 0).is_some() {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "elf.reloc.unknown_type",
                format!(
                    "{}: {unknown} relocation(s) of a type not known for this machine",
                    t.name
                ),
            )
            .at(t.file_range),
        );
    }
    if !t.applied_at_load || ctx.phdrs.is_empty() {
        return;
    }
    let loads: Vec<&ProgramHeader> = ctx
        .phdrs
        .iter()
        .filter(|p| p.p_type.value == PT_LOAD)
        .collect();
    let mut unmapped: Vec<&ElfRelocation> = Vec::new();
    let mut readonly: Vec<(&ElfRelocation, &ProgramHeader)> = Vec::new();
    for r in &t.entries {
        if kind_of(ctx.machine, r.r_type) == RelocKind::None {
            continue;
        }
        let a = r.r_offset.value;
        match loads
            .iter()
            .find(|p| a >= p.p_vaddr.value && a - p.p_vaddr.value < p.p_memsz.value)
        {
            None => unmapped.push(r),
            Some(p) if !p.perms().write => readonly.push((r, p)),
            _ => {}
        }
    }
    if let Some(first) = unmapped.first() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.reloc.place_unmapped",
                format!(
                    "{}: {} relocation(s) patch addresses outside every LOAD segment (first: {:#x})",
                    t.name,
                    unmapped.len(),
                    first.r_offset.value
                ),
            )
            .at(first.r_offset.span)
            .os("the dynamic linker writes there anyway: a crash, or a write into whatever is mapped"),
        );
    }
    if let Some((first, seg)) = readonly.first() {
        let declared = dyn_entry(ctx.dynamic, DT_TEXTREL).is_some()
            || dyn_entry(ctx.dynamic, DT_FLAGS).is_some_and(|f| f.value.value & DF_TEXTREL != 0);
        let os = if declared {
            "DT_TEXTREL is set: the dynamic linker makes the segment writable while relocating, \
             so code is briefly writable and its pages are no longer shared between processes"
        } else {
            "no DT_TEXTREL: the dynamic linker does not unprotect the segment, so the write faults at startup"
        };
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.reloc.textrel",
                format!(
                    "{}: {} relocation(s) patch the read-only segment LOAD #{} (first: {:#x}): text relocations",
                    t.name,
                    readonly.len(),
                    seg.index,
                    first.r_offset.value
                ),
            )
            .at(first.r_offset.span)
            .os(os),
        );
    }
}
