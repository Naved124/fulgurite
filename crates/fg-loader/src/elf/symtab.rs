//! Symbol tables (`.symtab`, `.dynsym`) and GNU symbol versioning.
//!
//! The dynamic symbol table is located two ways:
//! * through the **dynamic segment** (`DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` ...),
//!   which is what the dynamic linker actually uses and survives the removal of
//!   section headers;
//! * through the **section headers** (`.dynsym`), which are advisory.
//!
//! When both exist they are cross-checked, and the dynamic segment wins.

use super::consts::*;
use super::dynamic::DynamicEntry;
use super::phdr::{ProgramHeader, map_va, va_to_offset};
use super::section::SectionHeader;
use super::strtab::StringTable;
use crate::model::{Limits, Symbol, SymbolBinding, SymbolKind, SymbolTable, SymbolVersion};
use fg_core::{Anomaly, Bitness, ByteView, Field, OutOfBounds, Severity, Span, Va};
use serde::Serialize;
use std::collections::BTreeMap;

/// Where a symbol table was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum TableSource {
    /// Through a section header (index given).
    Section(u32),
    /// Through the dynamic segment (`DT_SYMTAB`).
    DynamicSegment,
}

/// One ELF symbol entry. Every field keeps its file offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfSymbol {
    /// Position in the table.
    pub index: u32,
    /// The entry's bytes.
    pub span: Span,
    /// Name offset in the linked string table.
    pub st_name: Field<u32>,
    /// Resolved name, if readable.
    pub name: Option<Field<String>>,
    /// Type (low 4 bits) and binding (high 4 bits).
    pub st_info: Field<u8>,
    /// Visibility (low 2 bits).
    pub st_other: Field<u8>,
    /// Section index, or a special value (`SHN_UNDEF`, `SHN_ABS`, `SHN_COMMON`, `SHN_XINDEX`).
    pub st_shndx: Field<u16>,
    /// Real section index when `st_shndx == SHN_XINDEX` (from `SHT_SYMTAB_SHNDX`).
    pub shndx_extended: Option<Field<u32>>,
    /// Value (usually an address).
    pub st_value: Field<u64>,
    /// Size.
    pub st_size: Field<u64>,
    /// Raw version index from the version table, if any.
    pub versym: Option<Field<u16>>,
    /// Resolved version.
    pub version: Option<SymbolVersion>,
}

impl ElfSymbol {
    /// `STT_*` type.
    pub fn st_type(&self) -> u8 {
        self.st_info.value & 0xf
    }
    /// `STB_*` binding.
    pub fn st_bind(&self) -> u8 {
        self.st_info.value >> 4
    }
    /// `STV_*` visibility.
    pub fn st_visibility(&self) -> u8 {
        self.st_other.value & 0x3
    }
    /// Name, or `""`.
    pub fn name_str(&self) -> &str {
        self.name.as_ref().map_or("", |n| n.value.as_str())
    }
    /// True if defined in this file.
    pub fn is_defined(&self) -> bool {
        self.st_shndx.value != SHN_UNDEF
    }
    /// Section index as `readelf -s` prints it (`UND`, `ABS`, `COM`, or a number).
    pub fn ndx_display(&self) -> String {
        match self.st_shndx.value {
            SHN_UNDEF => "UND".into(),
            SHN_ABS => "ABS".into(),
            SHN_COMMON => "COM".into(),
            SHN_XINDEX => self
                .shndx_extended
                .as_ref()
                .map_or("XINDEX".into(), |x| x.value.to_string()),
            n if n >= SHN_LORESERVE => format!("{n:#x}"),
            n => n.to_string(),
        }
    }
}

/// A parsed symbol table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfSymbolTable {
    /// Dynamic or static.
    pub table: SymbolTable,
    /// How it was found.
    pub source: TableSource,
    /// The table's bytes.
    pub span: Span,
    /// Entries in table order (index 0 is the reserved null symbol).
    pub symbols: Vec<ElfSymbol>,
}

impl ElfSymbolTable {
    /// Converts entries to the format-neutral model.
    pub(crate) fn to_neutral(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .map(|s| {
                let kind = match s.st_type() {
                    STT_NOTYPE => SymbolKind::NoType,
                    STT_OBJECT => SymbolKind::Object,
                    STT_FUNC => SymbolKind::Function,
                    STT_SECTION => SymbolKind::Section,
                    STT_FILE => SymbolKind::File,
                    STT_COMMON => SymbolKind::Common,
                    STT_TLS => SymbolKind::Tls,
                    STT_GNU_IFUNC => SymbolKind::IndirectFunction,
                    _ => SymbolKind::Other,
                };
                let binding = match s.st_bind() {
                    STB_LOCAL => SymbolBinding::Local,
                    STB_GLOBAL => SymbolBinding::Global,
                    STB_WEAK => SymbolBinding::Weak,
                    STB_GNU_UNIQUE => SymbolBinding::Unique,
                    _ => SymbolBinding::Other,
                };
                Symbol::new(
                    self.table,
                    s.index,
                    s.name_str().to_string(),
                    s.version.clone(),
                    Va(s.st_value.value),
                    s.st_size.value,
                    kind,
                    binding,
                    s.is_defined(),
                    s.span,
                )
            })
            .collect()
    }
}

/// Size of one entry: 16 bytes (32-bit) or 24 bytes (64-bit).
pub fn entry_size(bitness: Bitness) -> u64 {
    match bitness {
        Bitness::Bits32 => 16,
        Bitness::Bits64 => 24,
    }
}

fn parse_one(
    view: &ByteView<'_>,
    bitness: Bitness,
    index: u32,
    base: u64,
) -> Result<ElfSymbol, OutOfBounds> {
    if !view.contains(base, entry_size(bitness)) {
        return Err(OutOfBounds {
            offset: base,
            len: entry_size(bitness),
            available: view.len(),
        });
    }
    let (info, other, shndx, value, size) = match bitness {
        Bitness::Bits64 => (4, 5, 6, (8, 8), (16, 8)),
        Bitness::Bits32 => (12, 13, 14, (4, 4), (8, 4)),
    };
    Ok(ElfSymbol {
        index,
        span: Span::new(base, entry_size(bitness)),
        st_name: view.field_u32(base)?,
        name: None,
        st_info: view.field_u8(base + info)?,
        st_other: view.field_u8(base + other)?,
        st_shndx: view.field_u16(base + shndx)?,
        shndx_extended: None,
        st_value: view.field_uint(base + value.0, value.1)?,
        st_size: view.field_uint(base + size.0, size.1)?,
        versym: None,
        version: None,
    })
}

/// Where a table's pieces live in the file.
struct Location {
    source: TableSource,
    offset: u64,
    count: u64,
    strtab: Span,
    versym: Option<u64>,
    verneed: Option<(u64, u64)>,
    verdef: Option<(u64, u64)>,
    shndx: Option<u64>,
}

/// Maps version indexes to names.
#[derive(Default)]
struct Versions {
    needed: BTreeMap<u16, (String, String)>,
    defined: BTreeMap<u16, String>,
}

fn read_versions(
    view: &ByteView<'_>,
    loc: &Location,
    strings: &StringTable<'_>,
    limit: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Versions {
    let mut v = Versions::default();
    let mut broken = false;
    // Verneed: { u16 version, u16 cnt, u32 file, u32 aux, u32 next } (16 bytes)
    // Vernaux: { u32 hash, u16 flags, u16 other, u32 name, u32 next } (16 bytes)
    if let Some((mut at, count)) = loc.verneed {
        let mut walked = 0u32;
        'needs: for _ in 0..count.min(u64::from(limit)) {
            let (Ok(cnt), Ok(file), Ok(aux), Ok(next)) = (
                view.u16(at + 2),
                view.u32(at + 4),
                view.u32(at + 8),
                view.u32(at + 12),
            ) else {
                broken = true;
                break;
            };
            let file = strings.get(file).map(|f| f.value).unwrap_or_default();
            let mut a = at + u64::from(aux);
            for _ in 0..cnt {
                walked += 1;
                if walked > limit {
                    broken = true;
                    break 'needs;
                }
                let (Ok(other), Ok(name), Ok(anext)) =
                    (view.u16(a + 6), view.u32(a + 8), view.u32(a + 12))
                else {
                    broken = true;
                    break 'needs;
                };
                if let Some(n) = strings.get(name) {
                    v.needed.insert(other & 0x7fff, (n.value, file.clone()));
                }
                if anext == 0 {
                    break;
                }
                a += u64::from(anext);
            }
            if next == 0 {
                break;
            }
            at += u64::from(next);
        }
    }
    // Verdef:  { u16 version, u16 flags, u16 ndx, u16 cnt, u32 hash, u32 aux, u32 next } (20 bytes)
    // Verdaux: { u32 name, u32 next } (8 bytes); the first aux is the version's own name.
    if let Some((mut at, count)) = loc.verdef {
        for _ in 0..count.min(u64::from(limit)) {
            let (Ok(flags), Ok(ndx), Ok(aux), Ok(next)) = (
                view.u16(at + 2),
                view.u16(at + 4),
                view.u32(at + 12),
                view.u32(at + 16),
            ) else {
                broken = true;
                break;
            };
            if flags & VER_FLG_BASE == 0 {
                match view
                    .u32(at + u64::from(aux))
                    .ok()
                    .and_then(|n| strings.get(n))
                {
                    Some(n) => {
                        v.defined.insert(ndx & 0x7fff, n.value);
                    }
                    None => broken = true,
                }
            }
            if next == 0 {
                break;
            }
            at += u64::from(next);
        }
    }
    if broken {
        anomalies.push(Anomaly::new(Severity::Warning, "elf.version.chain_invalid",
            "a symbol-version chain points outside the file or exceeds the limit; some versions are missing"));
    }
    v
}

fn read_table(
    view: &ByteView<'_>,
    bitness: Bitness,
    table: SymbolTable,
    loc: &Location,
    limits: &Limits,
    anomalies: &mut Vec<Anomaly>,
) -> ElfSymbolTable {
    let label = match table {
        SymbolTable::Dynamic => "dynamic symbol table",
        _ => "static symbol table",
    };
    let ent = entry_size(bitness);
    let mut count = loc.count;
    if count > u64::from(limits.max_symbols) {
        anomalies.push(Anomaly::new(
            Severity::Error,
            "elf.symtab.limit",
            format!(
                "{label} claims {count} symbols, more than the limit of {}; reading the first {}",
                limits.max_symbols, limits.max_symbols
            ),
        ));
        count = u64::from(limits.max_symbols);
    }
    let strings = StringTable::new(*view, loc.strtab, limits.max_name_len);
    let versions = if table == SymbolTable::Dynamic && loc.versym.is_some() {
        read_versions(view, loc, &strings, limits.max_versions, anomalies)
    } else {
        Versions::default()
    };

    let mut symbols = Vec::new();
    let (mut bad_names, mut bad_versions) = (0u64, 0u64);
    for i in 0..count {
        let Some(base) = i.checked_mul(ent).and_then(|r| loc.offset.checked_add(r)) else {
            break;
        };
        let mut s = match parse_one(view, bitness, i as u32, base) {
            Ok(s) => s,
            Err(_) => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "elf.symtab.truncated",
                        format!("{label} claims {count} entries but the file ends after {i}"),
                    )
                    .at(Span::new(loc.offset, count.saturating_mul(ent))),
                );
                break;
            }
        };
        s.name = strings.get(s.st_name.value);
        if s.name.is_none() {
            bad_names += 1;
        }
        if s.st_shndx.value == SHN_XINDEX {
            s.shndx_extended = loc.shndx.and_then(|o| view.field_u32(o + i * 4).ok());
        }
        if let Some(vs) = loc.versym {
            s.versym = view.field_u16(vs + i * 2).ok();
            if let Some(raw) = s.versym.as_ref().map(|f| f.value) {
                let idx = raw & 0x7fff;
                if idx >= 2 {
                    let needed = || {
                        versions
                            .needed
                            .get(&idx)
                            .map(|(n, f)| SymbolVersion::new(n.clone(), Some(f.clone()), false))
                    };
                    // Defined symbols normally use a version definition, but copy-relocated
                    // data (e.g. `stdout` in an executable) carries the library's needed version.
                    s.version = if s.is_defined() {
                        versions
                            .defined
                            .get(&idx)
                            .map(|n| SymbolVersion::new(n.clone(), None, raw & VERSYM_HIDDEN == 0))
                            .or_else(needed)
                    } else {
                        needed()
                    };
                    if s.version.is_none() {
                        bad_versions += 1;
                    }
                }
            }
        }
        symbols.push(s);
    }
    if bad_names > 0 {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.symtab.name_invalid",
                format!("{bad_names} symbol name(s) in the {label} point outside its string table"),
            )
            .at(loc.strtab),
        );
    }
    if bad_versions > 0 {
        anomalies.push(Anomaly::new(Severity::Warning, "elf.version.index_invalid",
            format!("{bad_versions} symbol(s) in the {label} use a version index that no version table defines")));
    }
    ElfSymbolTable {
        table,
        source: loc.source,
        span: Span::new(loc.offset, count.saturating_mul(ent)),
        symbols,
    }
}

/// Dynamic tags whose addresses point at tables that commonly follow `.dynsym`.
const TABLE_TAGS: &[i64] = &[
    DT_STRTAB,
    DT_HASH,
    DT_GNU_HASH,
    DT_VERSYM,
    DT_VERNEED,
    DT_VERDEF,
    DT_RELA,
    DT_REL,
    DT_JMPREL,
];

/// One more than the highest symbol index used by any dynamic relocation
/// (`DT_RELA`, `DT_REL`, `DT_JMPREL`), or 0 if there are none.
fn reloc_symbol_bound(
    view: &ByteView<'_>,
    bitness: Bitness,
    phdrs: &[ProgramHeader],
    dynamic: &[DynamicEntry],
    limit: u32,
) -> u64 {
    let w = u64::from(bitness.word_size());
    let tables = [
        (DT_RELA, DT_RELASZ, true),
        (DT_REL, DT_RELSZ, false),
        (
            DT_JMPREL,
            DT_PLTRELSZ,
            dyn_value(dynamic, DT_PLTREL).is_none_or(|e| e.value.value as i64 == DT_RELA),
        ),
    ];
    let mut best = 0u64;
    for (addr_tag, size_tag, rela) in tables {
        let (Some(a), Some(sz)) = (dyn_value(dynamic, addr_tag), dyn_value(dynamic, size_tag))
        else {
            continue;
        };
        let Some(off) = va_to_offset(phdrs, a.value.value) else {
            continue;
        };
        let ent = if rela { 3 * w } else { 2 * w };
        for i in 0..(sz.value.value / ent).min(u64::from(limit)) {
            let Some(at) = i
                .checked_mul(ent)
                .and_then(|d| off.checked_add(d))
                .and_then(|a| a.checked_add(w))
            else {
                break;
            };
            let Ok(info) = view.uint(at, bitness.word_size()) else {
                break;
            };
            let sym = match bitness {
                Bitness::Bits64 => info >> 32,
                Bitness::Bits32 => info >> 8,
            };
            best = best.max(sym + 1);
        }
    }
    if best == 1 { 0 } else { best } // index 0 means "no symbol"
}

/// Number of dynamic symbols according to the GNU hash table at `off`.
fn gnu_hash_count(view: &ByteView<'_>, bitness: Bitness, off: u64, limit: u32) -> Option<u64> {
    let nbuckets = u64::from(view.u32(off).ok()?);
    let symoffset = u64::from(view.u32(off + 4).ok()?);
    let bloom_size = u64::from(view.u32(off + 8).ok()?);
    if nbuckets > u64::from(limit) || bloom_size > u64::from(limit) {
        return None;
    }
    let buckets = off
        .checked_add(16)?
        .checked_add(bloom_size.checked_mul(u64::from(bitness.word_size()))?)?;
    let mut max_bucket = 0u64;
    for i in 0..nbuckets {
        max_bucket = max_bucket.max(u64::from(view.u32(buckets + i * 4).ok()?));
    }
    if max_bucket == 0 {
        return Some(symoffset); // no hashed symbols: only the unhashed ones exist
    }
    if max_bucket < symoffset {
        return None;
    }
    let chains = buckets + nbuckets * 4;
    // Walk the last bucket's chain until its end marker (low bit set).
    for idx in (max_bucket..).take(limit as usize) {
        let entry = view.u32(chains + (idx - symoffset) * 4).ok()?;
        if entry & 1 == 1 {
            return Some(idx + 1);
        }
    }
    None
}

fn dyn_value(dynamic: &[DynamicEntry], tag: i64) -> Option<&DynamicEntry> {
    dynamic.iter().find(|d| d.tag.value == tag)
}

/// Locates the dynamic symbol table through the dynamic segment.
fn locate_dynamic(
    view: &ByteView<'_>,
    bitness: Bitness,
    phdrs: &[ProgramHeader],
    dynamic: &[DynamicEntry],
    section: Option<(u64, u64)>,
    limits: &Limits,
    anomalies: &mut Vec<Anomaly>,
) -> Option<Location> {
    let symtab = dyn_value(dynamic, DT_SYMTAB)?;
    let map = |tag: &str, e: &DynamicEntry, anomalies: &mut Vec<Anomaly>| {
        map_va(phdrs, tag, e, anomalies)
    };
    let offset = map("DT_SYMTAB", symtab, anomalies)?;
    let strtab_e = dyn_value(dynamic, DT_STRTAB)?;
    let strtab_off = map("DT_STRTAB", strtab_e, anomalies)?;
    let strsz = dyn_value(dynamic, DT_STRSZ).map_or(0, |e| e.value.value);
    if let Some(e) = dyn_value(dynamic, DT_SYMENT)
        && e.value.value != entry_size(bitness)
    {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.syment",
                format!(
                    "DT_SYMENT is {}, expected {}",
                    e.value.value,
                    entry_size(bitness)
                ),
            )
            .at(e.value.span),
        );
    }

    // The dynamic segment never states the symbol count, so it is bounded from
    // three independent pieces of evidence:
    //  * hash tables: SysV DT_HASH's nchain is exact; DT_GNU_HASH only covers
    //    defined symbols, so it is a lower bound (imports may lie outside it);
    //  * relocations: the highest symbol index any relocation uses + 1 (lower bound);
    //  * layout: the gap to the next dynamic table above DT_SYMTAB (upper bound).
    let ent = entry_size(bitness);
    let mut exact = None;
    let mut lower = 0u64;
    if let Some(e) = dyn_value(dynamic, DT_HASH) {
        exact = map("DT_HASH", e, anomalies)
            .and_then(|o| view.u32(o + 4).ok())
            .map(u64::from);
    }
    if let Some(e) = dyn_value(dynamic, DT_GNU_HASH) {
        match map("DT_GNU_HASH", e, anomalies)
            .and_then(|o| gnu_hash_count(view, bitness, o, limits.max_symbols))
        {
            Some(c) => lower = lower.max(c),
            None => anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.gnu_hash.invalid",
                    "the GNU hash table could not be read",
                )
                .at(e.value.span),
            ),
        }
    }
    lower = lower.max(reloc_symbol_bound(
        view,
        bitness,
        phdrs,
        dynamic,
        limits.max_symbols,
    ));
    let upper = TABLE_TAGS
        .iter()
        .filter_map(|t| dyn_value(dynamic, *t))
        .map(|e| e.value.value)
        .filter(|&a| a > symtab.value.value)
        .min()
        .map(|next| (next - symtab.value.value) / ent);

    let count = match (exact, section) {
        (Some(c), _) => c,
        // Section headers agree with the dynamic segment's bounds: trust them.
        (None, Some((sec_off, sec_count)))
            if sec_off == offset && sec_count >= lower && upper.is_none_or(|u| sec_count <= u) =>
        {
            sec_count
        }
        _ => match upper {
            Some(u) if u >= lower => {
                anomalies.push(Anomaly::new(Severity::Info, "elf.dynsym.count_estimated",
                    format!("dynamic symbol count {u} inferred from the table layout (at least {lower} are referenced)")));
                u
            }
            _ if lower > 0 => lower,
            _ => return None,
        },
    };

    let versym = dyn_value(dynamic, DT_VERSYM).and_then(|e| map("DT_VERSYM", e, anomalies));
    let verneed = dyn_value(dynamic, DT_VERNEED)
        .and_then(|e| map("DT_VERNEED", e, anomalies))
        .map(|o| {
            (
                o,
                dyn_value(dynamic, DT_VERNEEDNUM).map_or(0, |n| n.value.value),
            )
        });
    let verdef = dyn_value(dynamic, DT_VERDEF)
        .and_then(|e| map("DT_VERDEF", e, anomalies))
        .map(|o| {
            (
                o,
                dyn_value(dynamic, DT_VERDEFNUM).map_or(0, |n| n.value.value),
            )
        });
    Some(Location {
        source: TableSource::DynamicSegment,
        offset,
        count,
        strtab: Span::new(strtab_off, strsz),
        versym,
        verneed,
        verdef,
        shndx: None,
    })
}

/// Locates a symbol table of section type `sh_type` through the section headers.
fn locate_section(
    sections: &[SectionHeader],
    sh_type: u32,
    bitness: Bitness,
    anomalies: &mut Vec<Anomaly>,
) -> Option<Location> {
    let s = sections.iter().find(|s| s.sh_type.value == sh_type)?;
    let label = format!("section #{} {}", s.index, s.name_str());
    let ent = entry_size(bitness);
    if s.sh_entsize.value != 0 && s.sh_entsize.value != ent {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.symtab.entsize",
                format!(
                    "{label}: sh_entsize is {}, expected {ent}; using {ent}",
                    s.sh_entsize.value
                ),
            )
            .at(s.sh_entsize.span),
        );
    }
    let strtab = match sections.get(s.sh_link.value as usize) {
        Some(t) if t.sh_type.value == SHT_STRTAB => t.file_range(),
        _ => {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.symtab.strtab_invalid",
                    format!(
                        "{label}: sh_link {} is not a string table; names unavailable",
                        s.sh_link.value
                    ),
                )
                .at(s.sh_link.span),
            );
            Span::new(0, 0)
        }
    };
    let linked = |t: u32| {
        sections
            .iter()
            .find(|x| x.sh_type.value == t && x.sh_link.value == s.index)
    };
    // Version need/def tables link to the string table, not the symbol table.
    let first = |t: u32| {
        sections
            .iter()
            .find(|x| x.sh_type.value == t)
            .map(|x| (x.sh_offset.value, u64::from(x.sh_info.value)))
    };
    Some(Location {
        source: TableSource::Section(s.index),
        offset: s.sh_offset.value,
        count: s.sh_size.value / ent,
        strtab,
        versym: linked(SHT_GNU_VERSYM).map(|x| x.sh_offset.value),
        verneed: first(SHT_GNU_VERNEED),
        verdef: first(SHT_GNU_VERDEF),
        shndx: linked(SHT_SYMTAB_SHNDX).map(|x| x.sh_offset.value),
    })
}

/// Reads the dynamic and static symbol tables.
pub(crate) fn read_all(
    view: &ByteView<'_>,
    bitness: Bitness,
    sections: &[SectionHeader],
    phdrs: &[ProgramHeader],
    dynamic: &[DynamicEntry],
    limits: &Limits,
    anomalies: &mut Vec<Anomaly>,
) -> (Option<ElfSymbolTable>, Option<ElfSymbolTable>) {
    let dyn_section = locate_section(sections, SHT_DYNSYM, bitness, anomalies);
    let dyn_segment = locate_dynamic(
        view,
        bitness,
        phdrs,
        dynamic,
        dyn_section.as_ref().map(|l| (l.offset, l.count)),
        limits,
        anomalies,
    );

    if let (Some(sec), Some(seg)) = (&dyn_section, &dyn_segment)
        && (sec.offset != seg.offset || sec.count != seg.count)
    {
        anomalies.push(
            Anomaly::new(Severity::Warning, "elf.dynsym.mismatch",
                format!("section headers place .dynsym at {:#x} with {} entries, but the dynamic segment \
                    says {:#x} with {}; using the dynamic segment", sec.offset, sec.count, seg.offset, seg.count))
            .os("the dynamic linker only uses the dynamic segment"),
        );
    }
    let dynsym = dyn_segment
        .or(dyn_section)
        .map(|loc| read_table(view, bitness, SymbolTable::Dynamic, &loc, limits, anomalies));
    let symtab = locate_section(sections, SHT_SYMTAB, bitness, anomalies)
        .map(|loc| read_table(view, bitness, SymbolTable::Static, &loc, limits, anomalies));
    (dynsym, symtab)
}
