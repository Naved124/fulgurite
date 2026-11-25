// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Debug directory: where the PDB is, reproducibility hashes, CET marking.

use super::consts::*;
use super::section::Image;
use fg_core::{Anomaly, ByteView, Field, Severity, Span};
use serde::Serialize;

/// One debug directory entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DebugEntry {
    /// Time stamp.
    pub time_date_stamp: Field<u32>,
    /// Format major version.
    pub major_version: Field<u16>,
    /// Format minor version.
    pub minor_version: Field<u16>,
    /// `IMAGE_DEBUG_TYPE_*`.
    pub debug_type: Field<u32>,
    /// Size of the data.
    pub size_of_data: Field<u32>,
    /// RVA of the data when it is mapped (0 if not).
    pub address_of_raw_data: Field<u32>,
    /// File offset of the data.
    pub pointer_to_raw_data: Field<u32>,
    /// Decoded data.
    pub content: DebugContent,
    /// The entry's 28 bytes.
    pub span: Span,
}

impl DebugEntry {
    /// Display name of the type.
    pub fn type_name(&self) -> String {
        debug_type_name(self.debug_type.value)
            .map_or_else(|| format!("type {}", self.debug_type.value), str::to_string)
    }
}

/// Decoded debug data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum DebugContent {
    /// CodeView `RSDS`: the PDB a debugger loads, identified by GUID and age.
    CodeView {
        /// PDB GUID in registry form `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
        guid: Field<String>,
        /// Incremented each time the PDB is updated.
        age: Field<u32>,
        /// Path of the PDB at link time.
        path: Field<String>,
        /// The GUID and age as symbol servers spell them (the PDB's identity).
        symbol_server_key: String,
    },
    /// CodeView `NB10` (VC6-era PDB 2.0).
    CodeViewNb10 {
        /// Time-stamp signature.
        signature: Field<u32>,
        /// Age.
        age: Field<u32>,
        /// Path of the PDB.
        path: Field<String>,
    },
    /// Extended DLL characteristics (CET shadow-stack compatibility...).
    ExDllCharacteristics(Field<u32>),
    /// Counts of objects compiled with each security feature (MSVC).
    VcFeature {
        /// Objects built by compilers older than Visual C++ 11.
        pre_vc11: u32,
        /// C/C++ objects.
        c_cpp: u32,
        /// Objects compiled with `/GS` (stack cookies).
        gs: u32,
        /// Objects compiled with `/sdl`.
        sdl: u32,
        /// Objects compiled with `guardN`.
        guard_n: u32,
        /// The data's bytes.
        span: Span,
    },
    /// Hash of the build inputs (reproducible build; the time stamps hold parts of it).
    Repro(Option<Field<String>>),
    /// Not decoded.
    Other,
}

pub(crate) fn read(
    image: &Image<'_>,
    rva: u64,
    size: u64,
    max: u32,
    max_name_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<DebugEntry> {
    let v = &image.view;
    if !size.is_multiple_of(28) {
        anomalies.push(Anomaly::new(
            Severity::Info,
            "pe.debug.size",
            format!("debug directory size {size:#x} is not a multiple of 28"),
        ));
    }
    let mut out = Vec::new();
    for i in 0..(size / 28).min(u64::from(max)) {
        let Ok(at) = image.offset(rva + i * 28, 28) else {
            anomalies.push(Anomaly::new(
                Severity::Error,
                "pe.debug.truncated",
                format!(
                    "debug directory entry {i} at RVA {:#x} is not in the file",
                    rva + i * 28
                ),
            ));
            break;
        };
        let mut r = || -> Result<DebugEntry, fg_core::OutOfBounds> {
            let mut e = DebugEntry {
                time_date_stamp: v.field_u32(at + 4)?,
                major_version: v.field_u16(at + 8)?,
                minor_version: v.field_u16(at + 10)?,
                debug_type: v.field_u32(at + 12)?,
                size_of_data: v.field_u32(at + 16)?,
                address_of_raw_data: v.field_u32(at + 20)?,
                pointer_to_raw_data: v.field_u32(at + 24)?,
                content: DebugContent::Other,
                span: Span::new(at, 28),
            };
            e.content = decode(v, &e, max_name_len, anomalies);
            Ok(e)
        };
        match r() {
            Ok(e) => out.push(e),
            Err(_) => {
                anomalies.push(Anomaly::new(
                    Severity::Error,
                    "pe.debug.truncated",
                    format!("debug directory entry {i} at file offset {at:#x} is outside the file"),
                ));
                break;
            }
        }
    }
    out
}

fn decode(
    v: &ByteView<'_>,
    e: &DebugEntry,
    max_name_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> DebugContent {
    let off = u64::from(e.pointer_to_raw_data.value);
    let len = u64::from(e.size_of_data.value);
    if off == 0 || len == 0 {
        return DebugContent::Other;
    }
    if !v.contains(off, len) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.debug.data_outside",
                format!(
                    "{} debug data at file offset {off:#x} (+{len:#x}) is outside the file",
                    e.type_name()
                ),
            )
            .at(e.pointer_to_raw_data.span),
        );
        return DebugContent::Other;
    }
    let data = ByteView::new(v.bytes(off, len).unwrap_or(&[]), fg_core::Endian::Little);
    let at = |f: Field<u32>| Field::new(f.value, Span::new(f.span.offset.0 + off, f.span.len));
    match e.debug_type.value {
        IMAGE_DEBUG_TYPE_CODEVIEW => {
            let sig = data.u32(0).unwrap_or(0);
            let path = |start: u64| {
                data.cstr(start, max_name_len.min(len.saturating_sub(start)))
                    .ok()
                    .flatten()
                    .map(|s| {
                        Field::new(
                            String::from_utf8_lossy(s.value).into_owned(),
                            Span::new(off + s.span.offset.0, s.span.len),
                        )
                    })
                    .unwrap_or_else(|| {
                        Field::new(String::new(), Span::new(off + start.min(len), 0))
                    })
            };
            match sig {
                0x5344_5352 if len >= 24 => {
                    let b = data.bytes(4, 16).unwrap_or(&[0; 16]);
                    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                    let d2 = u16::from_le_bytes([b[4], b[5]]);
                    let d3 = u16::from_le_bytes([b[6], b[7]]);
                    let tail: String = b[8..].iter().map(|x| format!("{x:02X}")).collect();
                    let guid = format!(
                        "{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}",
                        &tail[..4],
                        &tail[4..]
                    );
                    let age = at(data
                        .field_u32(20)
                        .unwrap_or(Field::new(0, Span::new(20, 4))));
                    let key = format!("{d1:08X}{d2:04X}{d3:04X}{tail}{:X}", age.value);
                    DebugContent::CodeView {
                        guid: Field::new(guid, Span::new(off + 4, 16)),
                        age,
                        path: path(24),
                        symbol_server_key: key,
                    }
                }
                0x3031_424e if len >= 16 => DebugContent::CodeViewNb10 {
                    signature: at(data.field_u32(8).unwrap_or(Field::new(0, Span::new(8, 4)))),
                    age: at(data
                        .field_u32(12)
                        .unwrap_or(Field::new(0, Span::new(12, 4)))),
                    path: path(16),
                },
                _ => {
                    anomalies.push(
                        Anomaly::new(
                            Severity::Info,
                            "pe.debug.codeview_unknown",
                            format!("CodeView record with unknown signature {sig:#010x}"),
                        )
                        .at(Span::new(off, 4.min(len))),
                    );
                    DebugContent::Other
                }
            }
        }
        IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS if len >= 4 => {
            DebugContent::ExDllCharacteristics(at(data
                .field_u32(0)
                .unwrap_or(Field::new(0, Span::new(0, 4)))))
        }
        12 if len >= 20 => {
            let g = |i: u64| data.u32(i * 4).unwrap_or(0);
            DebugContent::VcFeature {
                pre_vc11: g(0),
                c_cpp: g(1),
                gs: g(2),
                sdl: g(3),
                guard_n: g(4),
                span: Span::new(off, 20),
            }
        }
        IMAGE_DEBUG_TYPE_REPRO => {
            // Either empty, or a length-prefixed hash.
            let hash = data.u32(0).ok().and_then(|n| {
                let n = u64::from(n);
                data.bytes(4, n).ok().map(|b| {
                    Field::new(
                        b.iter().map(|x| format!("{x:02x}")).collect(),
                        Span::new(off + 4, n),
                    )
                })
            });
            DebugContent::Repro(hash)
        }
        _ => DebugContent::Other,
    }
}
