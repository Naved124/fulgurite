// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Base relocations: the addresses the loader adjusts when the image cannot be
//! loaded at its preferred base (always, under ASLR).

use super::consts::*;
use super::section::Image;
use fg_core::{Anomaly, Field, Severity, Span};
use serde::Serialize;
use std::collections::BTreeSet;

/// One block of base relocations: the fix-ups for one 4 KiB page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BaseRelocBlock {
    /// RVA of the page.
    pub page_rva: Field<u32>,
    /// Size of the block in bytes, header included.
    pub block_size: Field<u32>,
    /// Number of 2-byte entries (padding entries included).
    pub entries: u32,
}

/// One decoded base relocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BaseReloc {
    pub rva: u64,
    pub r_type: u8,
    pub span: Span,
    pub stored: Option<Field<u64>>,
}

pub(crate) fn read(
    image: &Image<'_>,
    machine: u16,
    rva: u64,
    size: u64,
    max: u32,
    anomalies: &mut Vec<Anomaly>,
) -> (Vec<BaseRelocBlock>, Vec<BaseReloc>) {
    let mut blocks = Vec::new();
    let mut relocs = Vec::new();
    let mut unknown_types = BTreeSet::new();
    let mut unmapped = 0u32;
    let end = rva.saturating_add(size);
    let mut at = rva;
    'blocks: while at + 8 <= end {
        let (Ok(page), Ok(bsize)) = (image.u32(at), image.u32(at + 4)) else {
            anomalies.push(Anomaly::new(
                Severity::Error,
                "pe.reloc.truncated",
                format!("base relocation block at RVA {at:#x} cannot be read"),
            ));
            break;
        };
        let bs = u64::from(bsize.value);
        if bs < 8 || !bs.is_multiple_of(2) {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "pe.reloc.block_size",
                    format!("base relocation block at RVA {at:#x} has invalid size {bs:#x}"),
                )
                .at(bsize.span),
            );
            break;
        }
        if at + bs > end {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.reloc.truncated",
                    format!(
                        "base relocation block at RVA {at:#x} (size {bs:#x}) runs past the end of the directory"
                    ),
                )
                .at(bsize.span),
            );
        }
        let count = ((bs - 8) / 2) as u32;
        blocks.push(BaseRelocBlock {
            page_rva: page.clone(),
            block_size: bsize,
            entries: count,
        });
        let mut i = 0;
        while i < count {
            let e_rva = at + 8 + u64::from(i) * 2;
            if e_rva + 2 > end {
                break 'blocks;
            }
            let Ok(e) = image.u16(e_rva) else {
                break 'blocks;
            };
            i += 1;
            let r_type = (e.value >> 12) as u8;
            if r_type == IMAGE_REL_BASED_ABSOLUTE {
                continue; // padding
            }
            if r_type == IMAGE_REL_BASED_HIGHADJ {
                i += 1; // the next entry holds the low half of the adjustment
            }
            if relocs.len() as u32 >= max {
                anomalies.push(Anomaly::new(
                    Severity::Warning,
                    "pe.reloc.limit",
                    format!("more than {max} base relocations; the rest are ignored"),
                ));
                break 'blocks;
            }
            if base_reloc_name(machine, r_type).is_none() {
                unknown_types.insert(r_type);
            }
            let place = u64::from(page.value) + u64::from(e.value & 0xfff);
            if !image.is_mapped(place) {
                unmapped += 1;
            }
            let width = base_reloc_width(r_type);
            let stored = match width {
                2 | 4 | 8 => image.uint(place, width).ok(),
                _ => None,
            };
            relocs.push(BaseReloc {
                rva: place,
                r_type,
                span: e.span,
                stored,
            });
        }
        at += bs;
    }
    for t in unknown_types {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.reloc.unknown_type",
            format!("base relocation type {t} is not defined for this machine"),
        ));
    }
    if unmapped > 0 {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.reloc.place_unmapped",
            format!("{unmapped} base relocation(s) patch addresses outside every section"),
        ));
    }
    (blocks, relocs)
}
