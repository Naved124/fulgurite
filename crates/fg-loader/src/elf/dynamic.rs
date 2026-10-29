//! The dynamic section, read through the `PT_DYNAMIC` program header.

use fg_core::{Bitness, ByteView, Field};
use serde::Serialize;

/// One `Elf*_Dyn` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DynamicEntry {
    /// `d_tag` (`DT_*`), sign-extended.
    pub tag: Field<i64>,
    /// `d_val` / `d_ptr`.
    pub value: Field<u64>,
}

/// Size of one entry: 8 bytes (32-bit) or 16 bytes (64-bit).
pub fn entry_size(bitness: Bitness) -> u64 {
    u64::from(bitness.word_size()) * 2
}

/// Result of walking the dynamic array.
pub(crate) struct DynamicScan {
    pub entries: Vec<DynamicEntry>,
    pub terminated: bool,
    pub hit_limit: bool,
    pub truncated: bool,
}

/// Reads entries from `[offset, offset + size)` until `DT_NULL`, the end of the
/// range, the end of the file, or `limit` entries.
pub(crate) fn scan(
    view: &ByteView<'_>,
    bitness: Bitness,
    offset: u64,
    size: u64,
    limit: u32,
) -> DynamicScan {
    let w = bitness.word_size();
    let ent = entry_size(bitness);
    let mut out = DynamicScan {
        entries: Vec::new(),
        terminated: false,
        hit_limit: false,
        truncated: false,
    };
    let count = size / ent;
    for i in 0..count {
        if out.entries.len() as u64 >= u64::from(limit) {
            out.hit_limit = true;
            break;
        }
        let Some(base) = i.checked_mul(ent).and_then(|r| offset.checked_add(r)) else {
            out.truncated = true;
            break;
        };
        // The offset comes from the file: the value's position can pass 2^64
        // even where the tag's does not.
        let Some(value_at) = base.checked_add(u64::from(w)) else {
            out.truncated = true;
            break;
        };
        let (Ok(tag), Ok(value)) = (view.field_uint(base, w), view.field_uint(value_at, w)) else {
            out.truncated = true;
            break;
        };
        let tag = tag.map(|t| match bitness {
            Bitness::Bits32 => i64::from(t as u32 as i32),
            Bitness::Bits64 => t as i64,
        });
        if tag.value == super::consts::DT_NULL {
            out.terminated = true;
            break;
        }
        out.entries.push(DynamicEntry { tag, value });
    }
    out
}

/// Strings the dynamic section names: libraries and search paths.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DynamicStrings {
    /// `DT_NEEDED`: libraries to load, in order.
    pub needed: Vec<Field<String>>,
    /// `DT_SONAME`: the name other files record when they link against this one.
    pub soname: Option<Field<String>>,
    /// `DT_RPATH`: library search path, searched before `LD_LIBRARY_PATH` (legacy).
    pub rpath: Option<Field<String>>,
    /// `DT_RUNPATH`: library search path, searched after `LD_LIBRARY_PATH`.
    pub runpath: Option<Field<String>>,
}

/// Resolves the string-valued dynamic entries through `DT_STRTAB`.
pub(crate) fn read_strings(
    view: &ByteView<'_>,
    phdrs: &[super::phdr::ProgramHeader],
    entries: &[DynamicEntry],
    max_len: u64,
    anomalies: &mut Vec<fg_core::Anomaly>,
) -> DynamicStrings {
    use super::consts::*;
    use fg_core::{Anomaly, Severity, Span};
    let mut out = DynamicStrings::default();
    let wanted = |t: i64| matches!(t, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH);
    if !entries.iter().any(|e| wanted(e.tag.value)) {
        return out;
    }
    let find = |t: i64| entries.iter().find(|e| e.tag.value == t);
    let Some(strtab) = find(DT_STRTAB) else {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "elf.dynamic.no_strtab",
            "library names and search paths are present but DT_STRTAB is missing",
        ));
        return out;
    };
    let Some(off) = super::phdr::map_va(phdrs, "DT_STRTAB", strtab, anomalies) else {
        return out;
    };
    let size = find(DT_STRSZ).map_or(view.len().saturating_sub(off), |e| e.value.value);
    let table = super::strtab::StringTable::new(*view, Span::new(off, size), max_len);
    for e in entries.iter().filter(|e| wanted(e.tag.value)) {
        let name = u32::try_from(e.value.value).ok().and_then(|o| table.get(o));
        let Some(name) = name else {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.dynamic.string_invalid",
                    format!(
                        "dynamic tag {} names string offset {:#x}, which is not a valid string in DT_STRTAB",
                        e.tag.value, e.value.value
                    ),
                )
                .at(e.value.span),
            );
            continue;
        };
        match e.tag.value {
            DT_NEEDED => out.needed.push(name),
            DT_SONAME => out.soname = out.soname.take().or(Some(name)),
            DT_RPATH => out.rpath = out.rpath.take().or(Some(name)),
            _ => out.runpath = out.runpath.take().or(Some(name)),
        }
    }
    out
}
