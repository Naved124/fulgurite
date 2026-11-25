// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Program headers (`Elf32_Phdr` / `Elf64_Phdr`): what the OS loader maps.

use super::consts::{PF_R, PF_W, PF_X, p_type_name};
use super::dynamic::DynamicEntry;
use fg_core::{Anomaly, Bitness, ByteView, Field, OutOfBounds, Perms, Severity, Span};
use serde::Serialize;

/// One program header. Every field keeps its file offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProgramHeader {
    /// Position in the program header table.
    pub index: u32,
    /// The whole entry's bytes.
    pub span: Span,
    /// Segment type (`PT_*`).
    pub p_type: Field<u32>,
    /// Permission flags (`PF_R | PF_W | PF_X`).
    pub p_flags: Field<u32>,
    /// File offset of the segment's bytes.
    pub p_offset: Field<u64>,
    /// Virtual address.
    pub p_vaddr: Field<u64>,
    /// Physical address (usually equal to `p_vaddr`).
    pub p_paddr: Field<u64>,
    /// Bytes in the file.
    pub p_filesz: Field<u64>,
    /// Bytes in memory.
    pub p_memsz: Field<u64>,
    /// Alignment.
    pub p_align: Field<u64>,
}

impl ProgramHeader {
    /// `readelf`-style type name, or `None` for types this version does not name.
    pub fn type_name(&self) -> Option<&'static str> {
        p_type_name(self.p_type.value)
    }

    /// Memory permissions from `p_flags`.
    pub fn perms(&self) -> Perms {
        let f = self.p_flags.value;
        Perms::new(f & PF_R != 0, f & PF_W != 0, f & PF_X != 0)
    }

    /// File range of the segment's bytes.
    pub fn file_range(&self) -> Span {
        Span::new(self.p_offset.value, self.p_filesz.value)
    }
}

/// Size of one entry: 32 bytes (32-bit) or 56 bytes (64-bit).
pub fn entry_size(bitness: Bitness) -> u64 {
    match bitness {
        Bitness::Bits32 => 32,
        Bitness::Bits64 => 56,
    }
}

/// Parses one entry starting at `base`.
pub(crate) fn parse_one(
    view: &ByteView<'_>,
    bitness: Bitness,
    index: u32,
    base: u64,
) -> Result<ProgramHeader, OutOfBounds> {
    let at = |rel: u64| {
        base.checked_add(rel).ok_or(OutOfBounds {
            offset: base,
            len: rel,
            available: view.len(),
        })
    };
    let span = Span::new(base, entry_size(bitness));
    Ok(match bitness {
        Bitness::Bits64 => ProgramHeader {
            index,
            span,
            p_type: view.field_u32(at(0)?)?,
            p_flags: view.field_u32(at(4)?)?,
            p_offset: view.field_u64(at(8)?)?,
            p_vaddr: view.field_u64(at(16)?)?,
            p_paddr: view.field_u64(at(24)?)?,
            p_filesz: view.field_u64(at(32)?)?,
            p_memsz: view.field_u64(at(40)?)?,
            p_align: view.field_u64(at(48)?)?,
        },
        // The 32-bit layout puts p_flags after p_memsz.
        Bitness::Bits32 => ProgramHeader {
            index,
            span,
            p_type: view.field_u32(at(0)?)?,
            p_offset: view.field_uint(at(4)?, 4)?,
            p_vaddr: view.field_uint(at(8)?, 4)?,
            p_paddr: view.field_uint(at(12)?, 4)?,
            p_filesz: view.field_uint(at(16)?, 4)?,
            p_memsz: view.field_uint(at(20)?, 4)?,
            p_flags: view.field_u32(at(24)?)?,
            p_align: view.field_uint(at(28)?, 4)?,
        },
    })
}

/// Maps a dynamic entry's address to a file offset, reporting addresses that no
/// segment backs.
pub(crate) fn map_va(
    phdrs: &[ProgramHeader],
    tag: &str,
    e: &DynamicEntry,
    anomalies: &mut Vec<Anomaly>,
) -> Option<u64> {
    let off = va_to_offset(phdrs, e.value.value);
    if off.is_none() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.unmapped",
                format!(
                    "{tag} address {:#x} is not inside any LOAD segment's file bytes",
                    e.value.value
                ),
            )
            .at(e.value.span),
        );
    }
    off
}

/// [`va_to_offset`] for many addresses: the address space is cut at every
/// `PT_LOAD` boundary, and each piece remembers the first header (in header
/// order) that maps it, so a lookup is a binary search however many headers
/// there are.
pub(crate) struct LoadMap {
    /// Piece starts, ascending; piece `i` ends where piece `i + 1` starts.
    starts: Vec<u128>,
    /// For each piece, the first header mapping it: its address and offset.
    first: Vec<Option<(u64, u64)>>,
}

impl LoadMap {
    pub(crate) fn new(phdrs: &[ProgramHeader]) -> LoadMap {
        // Each header maps [vaddr, vaddr + len), where len stops before the
        // file offset would pass 2^64 (as `va_to_offset` skips those).
        let loads: Vec<(u128, u128, u64, u64)> = phdrs
            .iter()
            .filter(|p| p.p_type.value == super::consts::PT_LOAD)
            .filter_map(|p| {
                let (va, off) = (p.p_vaddr.value, p.p_offset.value);
                let len = u128::from(p.p_filesz.value).min(u128::from(u64::MAX - off) + 1);
                (len > 0).then(|| (u128::from(va), u128::from(va) + len, va, off))
            })
            .collect();
        let mut starts: Vec<u128> = loads.iter().flat_map(|l| [l.0, l.1]).collect();
        starts.sort_unstable();
        starts.dedup();
        let mut first = vec![None; starts.len()];
        // The next piece not yet given a header, at or after each piece
        // (path-compressed), so every piece is assigned once.
        let mut next: Vec<usize> = (0..=starts.len()).collect();
        fn find(next: &mut [usize], i: usize) -> usize {
            let mut r = i;
            while next[r] != r {
                r = next[r];
            }
            let mut j = i;
            while next[j] != r {
                let k = next[j];
                next[j] = r;
                j = k;
            }
            r
        }
        for &(lo, hi, va, off) in &loads {
            let a = starts.partition_point(|&s| s < lo);
            let b = starts.partition_point(|&s| s < hi);
            let mut i = find(&mut next, a);
            while i < b {
                first[i] = Some((va, off));
                next[i] = i + 1;
                i = find(&mut next, i + 1);
            }
        }
        LoadMap { starts, first }
    }

    /// The same as `va_to_offset(phdrs, va)`.
    pub(crate) fn offset(&self, va: u64) -> Option<u64> {
        let i = self
            .starts
            .partition_point(|&s| s <= u128::from(va))
            .checked_sub(1)?;
        let (base, off) = self.first[i]?;
        off.checked_add(va - base)
    }
}

/// File offset of virtual address `va`, using the `PT_LOAD` headers.
pub(crate) fn va_to_offset(phdrs: &[ProgramHeader], va: u64) -> Option<u64> {
    phdrs
        .iter()
        .filter(|p| p.p_type.value == super::consts::PT_LOAD)
        .find_map(|p| {
            let delta = va.checked_sub(p.p_vaddr.value)?;
            (delta < p.p_filesz.value)
                .then(|| p.p_offset.value.checked_add(delta))
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::Span;

    fn load(vaddr: u64, filesz: u64, offset: u64) -> ProgramHeader {
        let f = |v| Field::new(v, Span::new(0, 0));
        ProgramHeader {
            index: 0,
            span: Span::new(0, 0),
            p_type: Field::new(super::super::consts::PT_LOAD, Span::new(0, 0)),
            p_flags: Field::new(0, Span::new(0, 0)),
            p_offset: f(offset),
            p_vaddr: f(vaddr),
            p_paddr: f(vaddr),
            p_filesz: f(filesz),
            p_memsz: f(filesz),
            p_align: f(0),
        }
    }

    #[test]
    fn the_load_map_finds_what_a_scan_finds() {
        // Overlapping segments (the first in header order wins), empty ones,
        // ones that end at 2^64 and ones whose file offsets would pass it.
        let max = u64::MAX;
        let phdrs = [
            load(0x1000, 0x1000, 0),
            load(0x1800, 0x1000, 0x5000),
            load(0x1000, 0x100, 0x9000),
            load(0x3000, 0, 0x100),
            load(0x4000, 0x2000, max - 0x10),
            load(0x4000, 0x3000, 0x20),
            load(max - 0xf, 0x10, 0x30),
            load(max - 0x20, 0x100, 0x40),
            load(0, 0x10, max),
        ];
        let mut probes = vec![
            0,
            1,
            0xf,
            0x10,
            0x11,
            max,
            max - 1,
            max - 0xf,
            max - 0x10,
            max - 0x21,
        ];
        for p in &phdrs {
            let (v, s) = (p.p_vaddr.value, p.p_filesz.value);
            for d in [
                0,
                1,
                s.wrapping_sub(1),
                s,
                s.wrapping_add(1),
                0x10,
                0x11,
                0x12,
            ] {
                probes.push(v.wrapping_add(d));
                probes.push(v.wrapping_sub(d));
            }
        }
        // Every subset of the headers, in header order.
        for mask in 0u32..1 << phdrs.len() {
            let chosen: Vec<ProgramHeader> = phdrs
                .iter()
                .enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1)
                .map(|(_, p)| p.clone())
                .collect();
            let map = LoadMap::new(&chosen);
            for &va in &probes {
                assert_eq!(
                    map.offset(va),
                    va_to_offset(&chosen, va),
                    "{mask:#b} {va:#x}"
                );
            }
        }
    }
}
