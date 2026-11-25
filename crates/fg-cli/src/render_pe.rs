// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Human-readable output for PE files. Same conventions as `render`: every value
//! is followed by `@offset`, the file bytes it came from.

use crate::render::{at, row};
use fg_service::core::Bitness;
use fg_service::loader::pe::consts::{self, flag_names};
use fg_service::loader::pe::{DebugContent, ImportKind, PeInfo, UnwindInfo};
use fg_service::loader::{LoadedBinary, SymbolTable};
use std::fmt::Write as _;

/// `2026-10-10 11:11:05 UTC` for a Unix time stamp.
pub fn utc(secs: u32) -> String {
    let secs = i64::from(secs);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn overview(o: &mut String, b: &LoadedBinary, pe: &PeInfo) {
    let opt = &pe.optional;
    let fh = &pe.file_header;
    let bits = match b.bitness {
        Bitness::Bits32 => "PE32 (32-bit)",
        Bitness::Bits64 => "PE32+ (64-bit)",
    };
    let subsystem = consts::subsystem_name(opt.subsystem.value).map_or_else(
        || format!("subsystem {}", opt.subsystem.value),
        str::to_string,
    );
    row(
        o,
        "Format",
        &format!("{bits}, {subsystem}"),
        Some(opt.magic.span),
    );
    row(
        o,
        "Type",
        &format!(
            "{}  (Characteristics {:#06x}: {})",
            b.kind.name(),
            fh.characteristics.value,
            flag_names(fh.characteristics.value, consts::FILE_CHARACTERISTICS).join(", ")
        ),
        Some(fh.characteristics.span),
    );
    row(
        o,
        "Machine",
        &format!(
            "{}  ({} {:#x})",
            b.arch,
            consts::machine_name(fh.machine.value).unwrap_or("?"),
            fh.machine.value
        ),
        Some(fh.machine.span),
    );
    match &b.entry {
        Some(e) => row(o, "Entry", &e.value.to_string(), Some(e.span)),
        None => row(o, "Entry", "none (DLL without DllMain)", None),
    }
    row(
        o,
        "Image base",
        &format!("{:#x}", opt.image_base.value),
        Some(opt.image_base.span),
    );
    row(
        o,
        "Linked",
        &format!(
            "{:#010x} (as a date: {}; reproducible builds store a hash here)",
            fh.time_date_stamp.value,
            utc(fh.time_date_stamp.value)
        ),
        Some(fh.time_date_stamp.span),
    );
    row(
        o,
        "Linker",
        &format!(
            "{}.{}, needs OS {}.{}, subsystem {}.{}",
            opt.major_linker_version.value,
            opt.minor_linker_version.value,
            opt.major_operating_system_version.value,
            opt.minor_operating_system_version.value,
            opt.major_subsystem_version.value,
            opt.minor_subsystem_version.value
        ),
        Some(opt.major_linker_version.span),
    );
    row(
        o,
        "DLL flags",
        &format!(
            "{:#06x} [{}]",
            opt.dll_characteristics.value,
            flag_names(opt.dll_characteristics.value, consts::DLL_CHARACTERISTICS).join(", ")
        ),
        Some(opt.dll_characteristics.span),
    );
    if let Some(x) = pe.ex_dll_characteristics() {
        row(
            o,
            "Ex DLL flags",
            &format!(
                "{:#x} [{}]",
                x.value,
                flag_names(x.value, consts::EX_DLL_CHARACTERISTICS).join(", ")
            ),
            Some(x.span),
        );
    }
    let sum = if opt.checksum.value == 0 {
        "0 (not set)".to_string()
    } else if opt.checksum.value == pe.computed_checksum {
        format!("{:#x} (valid)", opt.checksum.value)
    } else {
        format!(
            "{:#x} (computed {:#x})",
            opt.checksum.value, pe.computed_checksum
        )
    };
    row(o, "Checksum", &sum, Some(opt.checksum.span));
    for (label, list) in [
        ("Libraries", &pe.imports),
        ("Delay-loaded", &pe.delay_imports),
    ] {
        for (i, d) in list.iter().enumerate() {
            row(
                o,
                if i == 0 { label } else { "" },
                &format!("{}  ({} imports)", d.name.value, d.entries.len()),
                Some(d.name.span),
            );
        }
    }
    if let Some(x) = &pe.exports
        && let Some(n) = &x.name
    {
        row(o, "Export name", &n.value, Some(n.span));
    }
    for d in &pe.debug {
        if let DebugContent::CodeView { path, .. } | DebugContent::CodeViewNb10 { path, .. } =
            &d.content
            && !path.value.is_empty()
        {
            row(o, "PDB", &path.value, Some(path.span));
        }
    }
    if let Some(id) = &b.build_id {
        row(
            o,
            "Build ID",
            &format!("{}  (PDB GUID + age)", id.value),
            Some(id.span),
        );
    }
    if let Some(r) = &pe.rich {
        row(
            o,
            "Rich header",
            &format!(
                "{} tool records, checksum {}",
                r.entries.len(),
                if r.checksum_valid() {
                    "valid"
                } else {
                    "MISMATCH (edited or copied)"
                }
            ),
            Some(r.span),
        );
    }
    for c in &pe.certificates {
        row(
            o,
            "Signature",
            &format!(
                "{} ({} bytes)",
                consts::certificate_type_name(c.cert_type.value).unwrap_or("unknown type"),
                c.data.len
            ),
            Some(c.length.span),
        );
    }
    if let Some(c) = &pe.clr {
        row(
            o,
            ".NET",
            &format!(
                "CLR header, runtime {}.{}, flags {:#x}",
                c.major_runtime_version.value, c.minor_runtime_version.value, c.flags.value
            ),
            Some(c.span),
        );
    }
    if let Some(ov) = &pe.overlay {
        row(
            o,
            "Overlay",
            &format!("{} bytes after the last section", ov.len),
            Some(*ov),
        );
    }
}

pub fn mapping(o: &mut String, b: &LoadedBinary, pe: &PeInfo) {
    let opt = &pe.optional;
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "Memory map       {} sections; image size {:#x}, section alignment {:#x}, file alignment {:#x}",
        pe.sections.len(),
        opt.size_of_image.value,
        opt.section_alignment.value,
        opt.file_alignment.value
    );
    let w = match b.bitness {
        Bitness::Bits32 => 10,
        Bitness::Bits64 => 18,
    };
    let _ = writeln!(
        o,
        "  {:>3}  {:<14} {:<w$} {:<10} {:<10} {:<10} {:<5} Defined at",
        "#", "Name", "VirtAddr", "MemSize", "FileOff", "FileSize", "Perms"
    );
    for (i, s) in b.segments.iter().enumerate() {
        let idx = if i == 0 {
            "-".to_string()
        } else {
            (i - 1).to_string()
        };
        let _ = writeln!(
            o,
            "  {:>3}  {:<14} {:#0w$x} {:#010x} {:#010x} {:#010x} {:<5} @{}",
            idx,
            s.name,
            s.va.0,
            s.mem_size,
            s.file_offset.0,
            s.file_size,
            s.perms.to_string(),
            at(s.defined_by)
        );
    }
    let _ = writeln!(o);
    let present: Vec<_> = opt
        .data_directories
        .iter()
        .filter(|d| d.is_present())
        .collect();
    let _ = writeln!(
        o,
        "Data directories {} of {} in use",
        present.len(),
        opt.number_of_rva_and_sizes.value
    );
    for d in present {
        let place = if usize::from(d.index) == consts::DIR_SECURITY {
            "file offset".to_string()
        } else {
            pe.section_at(u64::from(d.rva.value))
                .map_or_else(|| "headers / none".to_string(), |s| s.name.clone())
        };
        let _ = writeln!(
            o,
            "  {:>3}  {:<12} {:#010x} {:#010x}  {:<14} @{}",
            d.index,
            d.name(),
            d.rva.value,
            d.size.value,
            place,
            at(d.rva.span)
        );
    }
}

pub fn summary(o: &mut String, b: &LoadedBinary, pe: &PeInfo) {
    let _ = writeln!(o);
    let count = |k: ImportKind| -> (usize, usize) {
        let list = if k == ImportKind::Static {
            &pe.imports
        } else {
            &pe.delay_imports
        };
        (list.iter().map(|d| d.entries.len()).sum(), list.len())
    };
    let (n, d) = count(ImportKind::Static);
    let (dn, dd) = count(ImportKind::Delay);
    let _ = writeln!(
        o,
        "Imports          {n} from {d} DLL(s){} (`fulg imports`)",
        if dd > 0 {
            format!(", plus {dn} delay-loaded from {dd}")
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        o,
        "Exports          {}",
        match &pe.exports {
            Some(x) => format!("{} (`fulg exports`)", x.entries.len()),
            None => "none".to_string(),
        }
    );
    let base_relocs = b
        .relocations
        .iter()
        .filter(|r| r.table == "base relocations")
        .count();
    let _ = writeln!(
        o,
        "Relocations      {base_relocs} base relocations in {} page block(s); {} IAT slots (`fulg relocs`)",
        pe.base_reloc_blocks.len(),
        b.relocations.len() - base_relocs
    );
    let coff = b
        .symbols
        .iter()
        .filter(|s| s.table == SymbolTable::Coff)
        .count();
    let _ = writeln!(
        o,
        "Symbols          {}",
        if coff > 0 {
            format!("{coff} COFF symbols (`fulg symbols`)")
        } else {
            "none in the file (stripped; MSVC keeps them in the PDB)".to_string()
        }
    );
    if let Some(t) = &pe.tls {
        let _ = writeln!(
            o,
            "TLS              {} callback(s) run before the entry point",
            t.callbacks.len()
        );
    }
    if !pe.exception.is_empty() {
        let frags = pe.exception.iter().filter(|f| f.is_fragment()).count();
        let _ = writeln!(
            o,
            "Exception table  {} functions with unwind data{}",
            pe.exception.len() - frags,
            if frags > 0 {
                format!(", {frags} fragments")
            } else {
                String::new()
            }
        );
    }
    if let Some(l) = &pe.load_config {
        let mut parts = Vec::new();
        if l.value("SecurityCookie") != 0 {
            parts.push(format!("/GS cookie at {:#x}", l.value("SecurityCookie")));
        }
        if !l.guard_cf_functions.is_empty() {
            parts.push(format!("{} CFG targets", l.guard_cf_functions.len()));
        }
        if !l.se_handlers.is_empty() {
            parts.push(format!("{} SafeSEH handlers", l.se_handlers.len()));
        }
        if parts.is_empty() {
            parts.push("present".to_string());
        }
        let _ = writeln!(
            o,
            "Load config      {} ({:#x} bytes)",
            parts.join(", "),
            l.span.len
        );
    }
    if !pe.debug.is_empty() {
        let kinds: Vec<String> = pe.debug.iter().map(|d| d.type_name()).collect();
        let _ = writeln!(o, "Debug directory  {} (`fulg notes`)", kinds.join(", "));
    }
    if !pe.resources.is_empty() {
        let _ = writeln!(
            o,
            "Resources        {} (`fulg resources`)",
            pe.resources.len()
        );
    }
    let _ = writeln!(o, "Code seeds       {} (`fulg seeds`)", b.seeds.len());
}

/// `fulg sections` for PE: the section table in full.
pub fn sections(o: &mut String, pe: &PeInfo) {
    let _ = writeln!(
        o,
        "  {:>3}  {:<14} {:<10} {:<10} {:<10} {:<10} {:<5} {:<10}  {:<34} Defined at",
        "#",
        "Name",
        "VirtAddr",
        "VirtSize",
        "RawOffset",
        "RawSize",
        "Perms",
        "Flags",
        "Characteristics"
    );
    for s in &pe.sections {
        let names: Vec<String> = flag_names(
            s.characteristics.value & !consts::IMAGE_SCN_ALIGN_MASK & !0xe000_0000,
            consts::SECTION_CHARACTERISTICS,
        );
        let _ = writeln!(
            o,
            "  {:>3}  {:<14} {:#010x} {:#010x} {:#010x} {:#010x} {:<5} {:#010x}  {:<34} @{:#x}",
            s.index,
            s.name,
            s.virtual_address.value,
            s.virtual_size.value,
            s.pointer_to_raw_data.value,
            s.size_of_raw_data.value,
            s.perms().to_string(),
            s.characteristics.value,
            names.join(" "),
            s.span.offset.0
        );
    }
    let _ = writeln!(
        o,
        "\nThe OS maps VirtSize bytes at VirtAddr (relative to the image base) and copies at most\n\
         min(RawSize, VirtSize) bytes from RawOffset; the rest is zero-filled. `fulg info` shows the result."
    );
}

/// `fulg imports` for PE: grouped by DLL, with IAT slots.
pub fn imports(o: &mut String, pe: &PeInfo) {
    if pe.imports.is_empty() && pe.delay_imports.is_empty() {
        let _ = writeln!(o, "No imports.");
        return;
    }
    for d in pe.imports.iter().chain(&pe.delay_imports) {
        let how = match d.kind {
            ImportKind::Static => "resolved at startup",
            _ => "delay-loaded: resolved on first call",
        };
        let bound = match d.time_date_stamp.value {
            0 => "",
            0xffff_ffff => ", bound",
            _ => ", bound (old style)",
        };
        let _ = writeln!(
            o,
            "{}  ({} imports, {how}{bound}; IAT at RVA {:#x})  @{}",
            d.name.value,
            d.entries.len(),
            d.address_table.value,
            at(d.descriptor)
        );
        let _ = writeln!(
            o,
            "  {:<18} {:<8} {:<44} {:<18} Defined at",
            "IAT slot", "Hint", "Name", "Stored value"
        );
        for e in &d.entries {
            let name = match (&e.name, e.ordinal) {
                (Some(n), _) => n.value.clone(),
                (None, Some(ord)) => format!("#{ord} (by ordinal)"),
                _ => "?".to_string(),
            };
            let hint = e
                .hint
                .as_ref()
                .map_or_else(|| "-".to_string(), |h| h.value.to_string());
            let stored = e
                .iat_value
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| format!("{:#x}", v.value));
            let _ = writeln!(
                o,
                "  {:#018x} {:<8} {:<44} {:<18} @{:#x}",
                e.iat_va.0, hint, name, stored, e.thunk.span.offset.0
            );
        }
        let _ = writeln!(o);
    }
    if !pe.bound_imports.is_empty() {
        let _ = writeln!(
            o,
            "Bound imports (addresses pre-resolved against these DLL versions):"
        );
        for bi in &pe.bound_imports {
            let _ = writeln!(
                o,
                "  {:<32} time stamp {:#010x}  @{}",
                bi.name.value,
                bi.time_date_stamp.value,
                at(bi.span)
            );
        }
    }
}

/// `fulg exports` for PE.
pub fn exports(o: &mut String, b: &LoadedBinary, pe: &PeInfo) {
    let Some(x) = &pe.exports else {
        let _ = writeln!(o, "No exports.");
        return;
    };
    let _ = writeln!(
        o,
        "{}  ordinal base {}, {} address entries, {} names  @{}",
        x.name.as_ref().map_or("(unnamed)", |n| n.value.as_str()),
        x.ordinal_base.value,
        x.number_of_functions.value,
        x.number_of_names.value,
        at(x.span)
    );
    let _ = writeln!(
        o,
        "  {:>7}  {:<18} {:<8} {:<48} Defined at",
        "Ordinal", "Address", "Kind", "Name"
    );
    let base = pe.optional.image_base.value;
    for e in &x.entries {
        let names = if e.names.is_empty() {
            "(by ordinal only)".to_string()
        } else {
            e.names
                .iter()
                .map(|n| n.value.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let (addr, kind) = match &e.forwarder {
            Some(f) => (format!("-> {}", f.value), "forward"),
            None => {
                let kind = b
                    .symbols
                    .iter()
                    .find(|s| s.table == SymbolTable::Exports && s.ordinal == Some(e.ordinal))
                    .map_or("?", |s| crate::render::kind_name(s.kind));
                (
                    format!("{:#018x}", base.wrapping_add(u64::from(e.rva.value))),
                    kind,
                )
            }
        };
        let _ = writeln!(
            o,
            "  {:>7}  {:<18} {:<8} {:<48} @{:#x}",
            e.ordinal, addr, kind, names, e.rva.span.offset.0
        );
    }
}

/// `fulg notes` for PE: debug directory, Rich header, signatures.
pub fn notes(o: &mut String, pe: &PeInfo) {
    if pe.debug.is_empty() {
        let _ = writeln!(o, "No debug directory.");
    }
    for d in &pe.debug {
        let _ = writeln!(
            o,
            "Debug  {}  (time stamp {:#010x}, {} data bytes at file offset {:#x})  @{}",
            d.type_name(),
            d.time_date_stamp.value,
            d.size_of_data.value,
            d.pointer_to_raw_data.value,
            at(d.span)
        );
        match &d.content {
            DebugContent::CodeView {
                guid,
                age,
                path,
                symbol_server_key,
            } => {
                let _ = writeln!(o, "  PDB GUID      {}  @{}", guid.value, at(guid.span));
                let _ = writeln!(o, "  Age           {}  @{}", age.value, at(age.span));
                let _ = writeln!(o, "  PDB path      {:?}  @{}", path.value, at(path.span));
                let _ = writeln!(
                    o,
                    "  Symbol key    {symbol_server_key}  (what a symbol server looks the PDB up by)"
                );
            }
            DebugContent::CodeViewNb10 {
                signature,
                age,
                path,
            } => {
                let _ = writeln!(
                    o,
                    "  NB10 signature {:#010x}, age {}, PDB {:?}",
                    signature.value, age.value, path.value
                );
            }
            DebugContent::ExDllCharacteristics(f) => {
                let _ = writeln!(
                    o,
                    "  Flags         {:#x} [{}]  @{}",
                    f.value,
                    flag_names(f.value, consts::EX_DLL_CHARACTERISTICS).join(", "),
                    at(f.span)
                );
            }
            DebugContent::VcFeature {
                pre_vc11,
                c_cpp,
                gs,
                sdl,
                guard_n,
                span,
            } => {
                let _ = writeln!(
                    o,
                    "  Objects       pre-VC11 {pre_vc11}, C/C++ {c_cpp}, /GS {gs}, /sdl {sdl}, guardN {guard_n}  @{}",
                    at(*span)
                );
            }
            DebugContent::Repro(Some(h)) => {
                let _ = writeln!(o, "  Input hash    {}  @{}", h.value, at(h.span));
            }
            _ => {}
        }
    }
    if let Some(r) = &pe.rich {
        let _ = writeln!(
            o,
            "\nRich header  key {:#010x}, checksum {}  @{}",
            r.key.value,
            if r.checksum_valid() {
                "valid".to_string()
            } else {
                format!("MISMATCH (computed {:#010x})", r.computed_checksum)
            },
            at(r.span)
        );
        let _ = writeln!(o, "  {:<8} {:<8} {:>8}", "Product", "Build", "Objects");
        for e in &r.entries {
            let _ = writeln!(
                o,
                "  {:<#8x} {:<8} {:>8}  @{}",
                e.product,
                e.build,
                e.count,
                at(e.span)
            );
        }
    }
    for c in &pe.certificates {
        let _ = writeln!(
            o,
            "\nSignature  {} (revision {:#x}), {} bytes  @{}",
            consts::certificate_type_name(c.cert_type.value).unwrap_or("unknown type"),
            c.revision.value,
            c.data.len,
            at(c.data)
        );
    }
}

/// `fulg resources`.
pub fn resources(o: &mut String, pe: &PeInfo) {
    if pe.resources.is_empty() {
        let _ = writeln!(o, "No resources.");
        return;
    }
    let _ = writeln!(
        o,
        "  {:<14} {:<24} {:<8} {:<10} {:<10} {:<8} Data at",
        "Type", "Name", "Language", "RVA", "Size", "CodePage"
    );
    for r in &pe.resources {
        let p = |i: usize| r.path.get(i).map_or_else(String::new, |n| n.to_string());
        let data = r
            .data
            .map_or_else(|| "not in file".to_string(), |s| format!("@{}", at(s)));
        let _ = writeln!(
            o,
            "  {:<14} {:<24} {:<8} {:#010x} {:#010x} {:<8} {data}",
            r.type_name(),
            p(1),
            p(2),
            r.data_rva.value,
            r.size.value,
            r.code_page.value
        );
    }
}

/// Short description of the unwind data behind an exception-table seed.
pub fn unwind_note(pe: &PeInfo, span_offset: u64) -> Option<String> {
    let f = pe
        .exception
        .iter()
        .find(|f| f.span.offset.0 == span_offset)?;
    Some(match &f.info {
        Some(UnwindInfo::X64(u)) => format!(
            "prologue {} bytes, {} unwind codes{}",
            u.prolog_size.value,
            u.codes.len(),
            if u.handler.is_some() {
                ", has handler"
            } else {
                ""
            }
        ),
        Some(UnwindInfo::Arm64Packed(p)) => format!("packed, frame {} bytes", p.frame_size),
        Some(UnwindInfo::Arm64Xdata(x)) => format!(
            "{} epilogue scope(s), {} code words{}",
            x.epilogue_count,
            x.code_words,
            if x.exception_data {
                ", has handler"
            } else {
                ""
            }
        ),
        _ => return None,
    })
}
