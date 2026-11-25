// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! COFF symbol table and string table. Images keep them only when built by
//! MinGW-style toolchains without stripping; the Windows loader never reads them.

use super::consts::*;
use fg_core::{Anomaly, ByteView, Field, Severity, Span};
use serde::Serialize;

/// One COFF symbol record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CoffSymbol {
    /// Index in the table (auxiliary records count, as in the file).
    pub index: u32,
    /// Name, resolved through the string table for long names.
    pub name: String,
    /// Value: usually the offset inside the section.
    pub value: Field<u32>,
    /// 1-based section number; 0 = undefined, -1 = absolute, -2 = debug.
    pub section_number: Field<i16>,
    /// Type (`Type >> 4 == 2` means function).
    pub sym_type: Field<u16>,
    /// Storage class (external, static, file, ...).
    pub storage_class: Field<u8>,
    /// Number of auxiliary records that follow.
    pub aux_count: Field<u8>,
    /// The 18-byte record.
    pub span: Span,
}

impl CoffSymbol {
    /// True if the symbol names a function.
    pub fn is_function(&self) -> bool {
        self.sym_type.value >> 4 == IMAGE_SYM_DTYPE_FUNCTION
    }
}

/// Reads the string table that follows the symbols: a 4-byte size, then names.
pub(crate) fn string_table_size(v: &ByteView<'_>, symtab: u64, count: u64) -> Option<(u64, u32)> {
    let at = symtab.checked_add(count.checked_mul(COFF_SYMBOL_SIZE)?)?;
    v.u32(at).ok().map(|n| (at, n))
}

/// Resolves a section or symbol name that refers to the string table.
pub(crate) fn string_at(
    v: &ByteView<'_>,
    strtab: u64,
    strsize: u32,
    off: u64,
    max: u64,
) -> Option<String> {
    if off < 4 || off >= u64::from(strsize) {
        return None;
    }
    v.cstr(strtab + off, max.min(u64::from(strsize) - off))
        .ok()
        .flatten()
        .map(|s| String::from_utf8_lossy(s.value).into_owned())
}

pub(crate) fn read_symbols(
    v: &ByteView<'_>,
    symtab: u64,
    count: u32,
    max: u32,
    max_name_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<CoffSymbol> {
    let mut out = Vec::new();
    let strtab = string_table_size(v, symtab, u64::from(count));
    if count > max {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.coff.limit",
            format!("COFF symbol table has {count} records; only {max} are read"),
        ));
    }
    let mut i = 0u32;
    while i < count.min(max) {
        let at = symtab + u64::from(i) * COFF_SYMBOL_SIZE;
        let rec = || -> Result<CoffSymbol, fg_core::OutOfBounds> {
            let raw = v.bytes(at, 8)?;
            let name = if raw[..4] == [0; 4] {
                let off = u64::from(u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]));
                strtab
                    .and_then(|(t, n)| string_at(v, t, n, off, max_name_len))
                    .unwrap_or_default()
            } else {
                String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
            };
            Ok(CoffSymbol {
                index: i,
                name,
                value: v.field_u32(at + 8)?,
                section_number: v.field_u16(at + 12)?.map(|x| x as i16),
                sym_type: v.field_u16(at + 14)?,
                storage_class: v.field_u8(at + 16)?,
                aux_count: v.field_u8(at + 17)?,
                span: Span::new(at, COFF_SYMBOL_SIZE),
            })
        };
        match rec() {
            Ok(s) => {
                i = i.saturating_add(1 + u32::from(s.aux_count.value));
                out.push(s);
            }
            Err(_) => {
                anomalies.push(Anomaly::new(
                    Severity::Warning,
                    "pe.coff.truncated",
                    format!("COFF symbol {i} at file offset {at:#x} is outside the file"),
                ));
                break;
            }
        }
    }
    out
}
