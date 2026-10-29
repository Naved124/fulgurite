//! Import, delay-import and bound-import directories.

use super::section::{Image, RvaError};
use fg_core::{Anomaly, Field, Severity, Span, Va};
use serde::Serialize;

/// How a DLL's imports are bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum ImportKind {
    /// Resolved by the loader at startup.
    Static,
    /// Resolved on the first call, by a helper linked into the program.
    Delay,
}

/// One imported function or variable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ImportEntry {
    /// Lookup-table entry: an ordinal (high bit set) or the RVA of a hint/name pair.
    pub thunk: Field<u64>,
    /// Address of the IAT slot the loader (or the delay helper) fills with the
    /// function's address.
    pub iat_va: Va,
    /// What the file stores in that slot before it is filled (a copy of the
    /// lookup entry, a pre-bound address, or for delay imports the address of
    /// the stub that resolves it).
    pub iat_value: Option<Field<u64>>,
    /// Import by name: the name.
    pub name: Option<Field<String>>,
    /// Import by name: the index the DLL's export table is searched from first.
    pub hint: Option<Field<u16>>,
    /// Import by ordinal: the ordinal.
    pub ordinal: Option<u16>,
}

/// Delay-load descriptor fields that static imports do not have.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DelayFields {
    /// Bit 0 set: the fields are RVAs (every modern linker); clear: VAs (VC6).
    pub attributes: Field<u32>,
    /// Where the DLL's module handle is cached.
    pub module_handle: Field<u32>,
    /// Optional copy of the IAT with pre-bound addresses.
    pub bound_iat: Field<u32>,
    /// Optional copy of the IAT used to unload the DLL.
    pub unload_iat: Field<u32>,
}

/// One DLL in the import or delay-import directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ImportedDll {
    /// Static or delay-loaded.
    pub kind: ImportKind,
    /// DLL name.
    pub name: Field<String>,
    /// The descriptor's bytes.
    pub descriptor: Span,
    /// RVA of the import lookup (name) table; 0 if absent (the IAT is read instead).
    pub lookup_table: Field<u32>,
    /// RVA of the import address table.
    pub address_table: Field<u32>,
    /// Bind time stamp: 0 = not bound, `0xffffffff` = bound (see the bound-import directory).
    pub time_date_stamp: Field<u32>,
    /// Forwarder chain (static imports of old bound images).
    pub forwarder_chain: Option<Field<u32>>,
    /// Delay-load details.
    pub delay: Option<DelayFields>,
    /// The functions and variables imported from it.
    pub entries: Vec<ImportEntry>,
}

/// One DLL in the bound-import directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BoundImport {
    /// DLL name.
    pub name: Field<String>,
    /// Time stamp of the DLL version the addresses were bound against.
    pub time_date_stamp: Field<u32>,
    /// DLLs this one forwards to, with their time stamps.
    pub forwarders: Vec<(Field<String>, Field<u32>)>,
    /// The descriptor's bytes.
    pub span: Span,
}

pub(crate) struct Ctx<'i, 'a> {
    pub image: &'i Image<'a>,
    pub pe32_plus: bool,
    pub max_libraries: u32,
    pub max_entries: u32,
    pub max_name_len: u64,
    /// Imports still to be read from the whole file; `None` once the limit
    /// has been reported.
    pub budget: std::cell::Cell<Option<u32>>,
}

impl Ctx<'_, '_> {
    fn ptr_size(&self) -> u8 {
        if self.pe32_plus { 8 } else { 4 }
    }
    fn ordinal_flag(&self) -> u64 {
        if self.pe32_plus { 1 << 63 } else { 1 << 31 }
    }
}

/// Reads the import directory at `rva`.
pub(crate) fn read_imports(
    c: &Ctx<'_, '_>,
    rva: u64,
    size: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<ImportedDll> {
    let mut out = Vec::new();
    let mut at = rva;
    loop {
        if out.len() as u32 >= c.max_libraries {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.import.limit",
                format!(
                    "import directory lists more than {} DLLs; the rest are ignored",
                    c.max_libraries
                ),
            ));
            break;
        }
        // IMAGE_IMPORT_DESCRIPTOR: lookup table, time stamp, forwarder chain, name, IAT.
        let fields: Result<Vec<Field<u32>>, RvaError> =
            (0..5).map(|i| c.image.u32(at + i * 4)).collect();
        let f = match fields {
            Ok(f) => f,
            // A descriptor in zero-filled memory reads as zeros: the terminator.
            Err(RvaError::ZeroFill) => break,
            Err(RvaError::Unmapped) => {
                anomalies.push(Anomaly::new(
                    Severity::Error,
                    "pe.import.truncated",
                    format!("import descriptor at RVA {at:#x} is outside the image"),
                ));
                break;
            }
        };
        if f.iter().all(|x| x.value == 0) {
            if at + 20 > rva + size && size != 0 {
                anomalies.push(Anomaly::new(
                    Severity::Info,
                    "pe.import.size",
                    format!(
                        "import directory size {size:#x} does not cover the terminating descriptor at RVA {at:#x}"
                    ),
                ).os("Windows ignores the size and reads descriptors until an all-zero one"));
            }
            break;
        }
        let descriptor = Span::new(f[0].span.offset.0, 20);
        let [ilt, ts, fwd, name_rva, iat] = [&f[0], &f[1], &f[2], &f[3], &f[4]];
        let name = read_dll_name(
            c,
            u64::from(name_rva.value),
            name_rva,
            "pe.import.name_invalid",
            anomalies,
        );
        let entries = read_thunks(
            c,
            u64::from(ilt.value),
            u64::from(iat.value),
            &name.value,
            ImportKind::Static,
            anomalies,
        );
        if entries.is_empty() {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "pe.import.empty",
                    format!("import descriptor for {} imports nothing", name.value),
                )
                .at(descriptor),
            );
        }
        out.push(ImportedDll {
            kind: ImportKind::Static,
            name,
            descriptor,
            lookup_table: ilt.clone(),
            address_table: iat.clone(),
            time_date_stamp: ts.clone(),
            forwarder_chain: Some(fwd.clone()),
            delay: None,
            entries,
        });
        at += 20;
    }
    out
}

/// Reads the delay-import directory at `rva`.
pub(crate) fn read_delay_imports(
    c: &Ctx<'_, '_>,
    rva: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<ImportedDll> {
    let mut out = Vec::new();
    let mut at = rva;
    loop {
        if out.len() as u32 >= c.max_libraries {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.import.limit",
                format!(
                    "delay-import directory lists more than {} DLLs; the rest are ignored",
                    c.max_libraries
                ),
            ));
            break;
        }
        // ImgDelayDescr: attributes, name, module handle, IAT, INT, bound IAT, unload IAT, time stamp.
        let fields: Result<Vec<Field<u32>>, RvaError> =
            (0..8).map(|i| c.image.u32(at + i * 4)).collect();
        let f = match fields {
            Ok(f) => f,
            Err(RvaError::ZeroFill) => break,
            Err(RvaError::Unmapped) => {
                anomalies.push(Anomaly::new(
                    Severity::Error,
                    "pe.delay.truncated",
                    format!("delay-import descriptor at RVA {at:#x} is outside the image"),
                ));
                break;
            }
        };
        if f.iter().all(|x| x.value == 0) || f[1].value == 0 {
            break;
        }
        let rva_based = f[0].value & 1 != 0;
        // Version 1 descriptors (VC6) hold VAs; convert them.
        let to_rva = |x: &Field<u32>| -> u64 {
            let v = u64::from(x.value);
            if rva_based || v == 0 {
                v
            } else {
                c.image.rva_of(v).unwrap_or(u64::MAX)
            }
        };
        if !rva_based {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "pe.delay.va_based",
                    "delay-import descriptor uses virtual addresses (pre-VC7 format)",
                )
                .at(f[0].span),
            );
        }
        let descriptor = Span::new(f[0].span.offset.0, 32);
        let name = read_dll_name(c, to_rva(&f[1]), &f[1], "pe.delay.name_invalid", anomalies);
        let entries = read_thunks(
            c,
            to_rva(&f[4]),
            to_rva(&f[3]),
            &name.value,
            ImportKind::Delay,
            anomalies,
        );
        out.push(ImportedDll {
            kind: ImportKind::Delay,
            name,
            descriptor,
            lookup_table: f[4].clone(),
            address_table: f[3].clone(),
            time_date_stamp: f[7].clone(),
            forwarder_chain: None,
            delay: Some(DelayFields {
                attributes: f[0].clone(),
                module_handle: f[2].clone(),
                bound_iat: f[5].clone(),
                unload_iat: f[6].clone(),
            }),
            entries,
        });
        at += 32;
    }
    out
}

fn read_dll_name(
    c: &Ctx<'_, '_>,
    rva: u64,
    field: &Field<u32>,
    code: &'static str,
    anomalies: &mut Vec<Anomaly>,
) -> Field<String> {
    match c.image.cstr(rva, c.max_name_len) {
        Ok(Some(s)) if !s.value.is_empty() => s,
        _ => {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    code,
                    format!("DLL name at RVA {rva:#x} cannot be read"),
                )
                .at(field.span),
            );
            Field::new(String::new(), field.span)
        }
    }
}

/// Walks a lookup table (or the IAT when there is none) to its zero terminator.
fn read_thunks(
    c: &Ctx<'_, '_>,
    ilt: u64,
    iat: u64,
    dll: &str,
    kind: ImportKind,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<ImportEntry> {
    let size = c.ptr_size();
    let step = u64::from(size);
    // Without a lookup table the names are read from the IAT itself (old
    // Borland linkers); that only works before the IAT is overwritten.
    let table = if ilt != 0 { ilt } else { iat };
    if ilt == 0 && kind == ImportKind::Static {
        anomalies.push(Anomaly::new(
            Severity::Info,
            "pe.import.no_lookup_table",
            format!("imports from {dll} have no lookup table; names are read from the IAT"),
        ));
    }
    let mut out = Vec::new();
    for i in 0.. {
        match c.budget.get() {
            None => break,
            Some(0) => {
                anomalies.push(Anomaly::new(
                    Severity::Warning,
                    "pe.import.total_limit",
                    "the file lists more imports than the limit; the rest are ignored",
                ));
                c.budget.set(None);
                break;
            }
            Some(_) => {}
        }
        if i >= c.max_entries {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                if kind == ImportKind::Static {
                    "pe.import.limit"
                } else {
                    "pe.delay.limit"
                },
                format!(
                    "more than {} imports from {dll}; the rest are ignored",
                    c.max_entries
                ),
            ));
            break;
        }
        let off = u64::from(i) * step;
        let thunk = match c.image.uint(table + off, size) {
            Ok(t) => t,
            Err(RvaError::ZeroFill) => break,
            Err(RvaError::Unmapped) => {
                anomalies.push(Anomaly::new(
                    Severity::Error,
                    if kind == ImportKind::Static {
                        "pe.import.thunk_unmapped"
                    } else {
                        "pe.delay.thunk_unmapped"
                    },
                    format!(
                        "import lookup entry {i} for {dll} at RVA {:#x} is outside the image",
                        table + off
                    ),
                ));
                break;
            }
        };
        if thunk.value == 0 {
            break;
        }
        let iat_rva = iat.wrapping_add(off);
        let iat_value = c.image.uint(iat_rva, size).ok();
        let (name, hint, ordinal) = if thunk.value & c.ordinal_flag() != 0 {
            (None, None, Some(thunk.value as u16))
        } else {
            let hn = thunk.value & 0x7fff_ffff;
            let hint = c.image.u16(hn).ok();
            let name = c.image.cstr(hn + 2, c.max_name_len).ok().flatten();
            if name.as_ref().is_none_or(|n| n.value.is_empty()) {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        if kind == ImportKind::Static {
                            "pe.import.name_invalid"
                        } else {
                            "pe.delay.name_invalid"
                        },
                        format!(
                            "import {i} from {dll}: name at RVA {:#x} cannot be read",
                            hn + 2
                        ),
                    )
                    .at(thunk.span),
                );
            }
            (name, hint, None)
        };
        c.budget.set(c.budget.get().map(|n| n - 1));
        out.push(ImportEntry {
            thunk,
            iat_va: Va(c.image.image_base.wrapping_add(iat_rva)),
            iat_value,
            name,
            hint,
            ordinal,
        });
    }
    out
}

/// Reads the bound-import directory at `rva`.
pub(crate) fn read_bound(
    c: &Ctx<'_, '_>,
    rva: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<BoundImport> {
    let mut out = Vec::new();
    let mut at = rva;
    let mut count = 0u32;
    loop {
        if count >= c.max_libraries {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.bound.limit",
                format!(
                    "bound-import directory lists more than {} DLLs",
                    c.max_libraries
                ),
            ));
            break;
        }
        // IMAGE_BOUND_IMPORT_DESCRIPTOR: time stamp, name offset, forwarder count.
        let (Ok(ts), Ok(name_off), Ok(nfwd)) =
            (c.image.u32(at), c.image.u16(at + 4), c.image.u16(at + 6))
        else {
            anomalies.push(Anomaly::new(
                Severity::Warning,
                "pe.bound.truncated",
                format!("bound-import descriptor at RVA {at:#x} cannot be read"),
            ));
            break;
        };
        if ts.value == 0 && name_off.value == 0 && nfwd.value == 0 {
            break;
        }
        let read_name = |off: u16| {
            c.image
                .cstr(rva + u64::from(off), c.max_name_len)
                .ok()
                .flatten()
                .unwrap_or_else(|| Field::new(String::new(), Span::new(0, 0)))
        };
        let span = ts.span;
        let name = read_name(name_off.value);
        let mut forwarders = Vec::new();
        for k in 0..u64::from(nfwd.value) {
            let r = at + 8 + k * 8;
            if let (Ok(fts), Ok(foff)) = (c.image.u32(r), c.image.u16(r + 4)) {
                forwarders.push((read_name(foff.value), fts));
            }
        }
        let len = 8 + u64::from(nfwd.value) * 8;
        out.push(BoundImport {
            name,
            time_date_stamp: ts,
            forwarders,
            span: Span::new(span.offset.0, len),
        });
        at += len;
        count += 1;
    }
    out
}
