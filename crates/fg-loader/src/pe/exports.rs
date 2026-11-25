// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Export directory.

use super::section::{Image, RvaError};
use fg_core::{Anomaly, Field, Severity, Span};
use serde::Serialize;

/// The export directory header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ExportDirectory {
    /// Name the DLL was linked as.
    pub name: Option<Field<String>>,
    /// Time stamp.
    pub time_date_stamp: Field<u32>,
    /// Ordinal of the first address-table entry.
    pub ordinal_base: Field<u32>,
    /// Entries in the address table.
    pub number_of_functions: Field<u32>,
    /// Entries in the name tables.
    pub number_of_names: Field<u32>,
    /// RVA of the address table.
    pub address_of_functions: Field<u32>,
    /// RVA of the name pointer table.
    pub address_of_names: Field<u32>,
    /// RVA of the name ordinal table.
    pub address_of_name_ordinals: Field<u32>,
    /// The header's 40 bytes.
    pub span: Span,
    /// Exports, by ordinal.
    pub entries: Vec<ExportEntry>,
}

/// One exported function or variable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ExportEntry {
    /// Ordinal (base + position in the address table).
    pub ordinal: u32,
    /// Address-table entry: the RVA of the code or data.
    pub rva: Field<u32>,
    /// Names that refer to this entry (none for ordinal-only exports).
    pub names: Vec<Field<String>>,
    /// For a forwarder (an RVA inside the export directory): `DLL.Function` or `DLL.#ordinal`.
    pub forwarder: Option<Field<String>>,
}

pub(crate) fn read(
    image: &Image<'_>,
    rva: u64,
    size: u64,
    max_entries: u32,
    max_name_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Option<ExportDirectory> {
    let f: Result<Vec<Field<u32>>, RvaError> = (0..10).map(|i| image.u32(rva + i * 4)).collect();
    let Ok(f) = f else {
        anomalies.push(Anomaly::new(
            Severity::Error,
            "pe.export.truncated",
            format!("export directory at RVA {rva:#x} cannot be read"),
        ));
        return None;
    };
    // Characteristics, TimeDateStamp, Major/Minor (one dword), Name, Base, counts, tables.
    let span = Span::new(f[0].span.offset.0, 40);
    let name = image
        .cstr(u64::from(f[3].value), max_name_len)
        .ok()
        .flatten();
    let base = f[4].clone();
    let nfunc = f[5].value;
    let nnames = f[6].value;
    let (eat, enpt, eot) = (
        u64::from(f[7].value),
        u64::from(f[8].value),
        u64::from(f[9].value),
    );
    let in_dir = |r: u64| r >= rva && r - rva < size;

    let mut entries: Vec<ExportEntry> = Vec::new();
    let nfunc_read = nfunc.min(max_entries);
    if nfunc > max_entries {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.export.limit",
                format!("export address table has {nfunc} entries; only {max_entries} are read"),
            )
            .at(f[5].span),
        );
    }
    // Position in the address table -> index in `entries`.
    let mut slot = std::collections::HashMap::new();
    for i in 0..nfunc_read {
        let r = match image.u32(eat + u64::from(i) * 4) {
            Ok(r) => r,
            Err(_) => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Error,
                        "pe.export.truncated",
                        format!(
                            "export address table entry {i} at RVA {:#x} cannot be read",
                            eat + u64::from(i) * 4
                        ),
                    )
                    .at(f[7].span),
                );
                break;
            }
        };
        if r.value == 0 {
            continue;
        }
        let forwarder = in_dir(u64::from(r.value))
            .then(|| image.cstr(u64::from(r.value), max_name_len).ok().flatten())
            .flatten();
        slot.insert(i, entries.len());
        entries.push(ExportEntry {
            ordinal: base.value.wrapping_add(i),
            rva: r,
            names: Vec::new(),
            forwarder,
        });
    }
    let nnames_read = nnames.min(max_entries);
    let mut previous: Option<String> = None;
    let mut unsorted = false;
    for k in 0..nnames_read {
        let (Ok(np), Ok(ord)) = (
            image.u32(enpt + u64::from(k) * 4),
            image.u16(eot + u64::from(k) * 2),
        ) else {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "pe.export.truncated",
                    format!("export name {k} cannot be read"),
                )
                .at(f[8].span),
            );
            break;
        };
        let Some(name) = image.cstr(u64::from(np.value), max_name_len).ok().flatten() else {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.export.name_invalid",
                    format!("export name {k} at RVA {:#x} cannot be read", np.value),
                )
                .at(np.span),
            );
            continue;
        };
        if previous
            .as_ref()
            .is_some_and(|p| p.as_bytes() > name.value.as_bytes())
        {
            unsorted = true;
        }
        previous = Some(name.value.clone());
        match slot.get(&u32::from(ord.value)) {
            Some(&e) => entries[e].names.push(name),
            None => anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.export.ordinal_invalid",
                format!(
                    "export {:?} refers to address-table entry {} which is empty or beyond the {nfunc} entries",
                    name.value, ord.value
                ),
            ).at(ord.span)),
        }
    }
    if unsorted {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.export.unsorted",
                "export names are not in sorted order",
            )
            .at(f[8].span)
            .os(
                "GetProcAddress binary-searches the names, so some exports cannot be found by name",
            ),
        );
    }
    Some(ExportDirectory {
        name,
        time_date_stamp: f[1].clone(),
        ordinal_base: base,
        number_of_functions: f[5].clone(),
        number_of_names: f[6].clone(),
        address_of_functions: f[7].clone(),
        address_of_names: f[8].clone(),
        address_of_name_ordinals: f[9].clone(),
        span,
        entries,
    })
}
