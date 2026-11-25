// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Human-readable output. Every value is followed by `@offset`, the file bytes it
//! came from, so any line of output can be checked against a hex dump.

use fg_service::Session;
use fg_service::core::{Anomaly, Bitness, Endian, Severity, Span};
use fg_service::loader::elf::{ElfInfo, consts};
use fg_service::loader::elf::{NoteContent, NoteSource, RelocFormat};
use fg_service::loader::{
    LoadedBinary, Mitigation, RelocKind, Relocation, SeedKind, Symbol, SymbolBinding, SymbolKind,
    SymbolTable, Verdict,
};
use std::fmt::Write as _;

pub(crate) const LABEL: usize = 13;

pub fn info(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{:LABEL$}{}  ({} bytes)",
        "File",
        session.path().display(),
        group(b.file_size)
    );
    if let Some(pe) = b.pe() {
        crate::render_pe::overview(&mut o, b, pe);
        crate::render_pe::mapping(&mut o, b, pe);
        crate::render_pe::summary(&mut o, b, pe);
        mitigations(&mut o, b);
        anomalies(&mut o, &b.anomalies);
        return o;
    }
    match b.elf() {
        Some(elf) => elf_overview(&mut o, b, elf),
        None => {
            let _ = writeln!(o, "{:LABEL$}{:?}", "Format", b.format);
        }
    }
    segments(&mut o, b);
    sections_summary(&mut o, b);
    mitigations(&mut o, b);
    anomalies(&mut o, &b.anomalies);
    o
}

fn elf_overview(o: &mut String, b: &LoadedBinary, elf: &ElfInfo) {
    let h = &elf.header;
    let bits = match b.bitness {
        Bitness::Bits32 => "ELF32",
        Bitness::Bits64 => "ELF64",
    };
    let endian = match b.endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    };
    let _ = writeln!(
        o,
        "{:LABEL$}{bits}, {endian}, OS/ABI {} ({})",
        "Format",
        consts::osabi_name(h.ident.osabi.value),
        h.ident.osabi.value
    );
    row(
        o,
        "Type",
        &format!(
            "{}  (e_type {})",
            b.kind.name(),
            consts::e_type_name(h.e_type.value)
        ),
        Some(h.e_type.span),
    );
    row(
        o,
        "Machine",
        &format!("{}  (e_machine {})", b.arch, h.e_machine.value),
        Some(h.e_machine.span),
    );
    match &b.entry {
        Some(e) => row(o, "Entry", &e.value.to_string(), Some(e.span)),
        None => row(o, "Entry", "none", None),
    }
    if let Some(i) = &elf.interpreter {
        row(o, "Interpreter", &i.value, Some(i.span));
    }
    let st = &elf.strings;
    if let Some(s) = &st.soname {
        row(o, "SONAME", &s.value, Some(s.span));
    }
    for (i, lib) in st.needed.iter().enumerate() {
        row(
            o,
            if i == 0 { "Libraries" } else { "" },
            &lib.value,
            Some(lib.span),
        );
    }
    if let Some(p) = &st.rpath {
        row(o, "RPATH", &p.value, Some(p.span));
    }
    if let Some(p) = &st.runpath {
        row(o, "RUNPATH", &p.value, Some(p.span));
    }
    if let Some(id) = &b.build_id {
        row(o, "Build ID", &id.value, Some(id.span));
    }
}

fn segments(o: &mut String, b: &LoadedBinary) {
    let Some(elf) = b.elf() else { return };
    let h = &elf.header;
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "Program headers  {} entries at offset {:#x}, {} bytes each",
        elf.phnum, h.e_phoff.value, h.e_phentsize.value
    );
    if elf.program_headers.is_empty() {
        let _ = writeln!(o, "  (none)");
        return;
    }
    let w = match b.bitness {
        Bitness::Bits32 => 8,
        Bitness::Bits64 => 16,
    };
    let _ = writeln!(
        o,
        "  {:>3}  {:<14} {:<10} {:<w2$} {:<10} {:<10} {:<5} {:<8} Defined at",
        "#",
        "Type",
        "Offset",
        "VirtAddr",
        "FileSiz",
        "MemSiz",
        "Flags",
        "Align",
        w2 = w + 2
    );
    for p in &elf.program_headers {
        let ty = p
            .type_name()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{:#x}", p.p_type.value));
        let _ = writeln!(
            o,
            "  {:>3}  {:<14} {:#010x} {:#0w2$x} {:#010x} {:#010x} {:<5} {:<#8x} @{:#x}",
            p.index,
            ty,
            p.p_offset.value,
            p.p_vaddr.value,
            p.p_filesz.value,
            p.p_memsz.value,
            p.perms().to_string(),
            p.p_align.value,
            p.span.offset.0,
            w2 = w + 2
        );
    }
    if let Some(ext) = &elf.phnum_extended {
        let _ = writeln!(
            o,
            "  (count {} taken from section header 0, @{:#x})",
            ext.value, ext.span.offset.0
        );
    }
}

fn mitigations(o: &mut String, b: &LoadedBinary) {
    let _ = writeln!(o);
    let _ = writeln!(o, "Mitigations");
    for m in b.mitigations.all() {
        mitigation(o, m);
    }
}

fn mitigation(o: &mut String, m: &Mitigation) {
    let verdict = match (m.verdict, m.name) {
        (Verdict::Enabled, "RELRO") => "full",
        (Verdict::Enabled, _) => "yes",
        (Verdict::Partial, _) => "partial",
        (Verdict::Disabled, _) => "no",
        (Verdict::NotApplicable, _) => "n/a",
        (Verdict::Unknown, _) => "unknown",
        _ => "?",
    };
    let _ = writeln!(o, "  {:<8}{:<9}{}", m.name, verdict, m.summary);
    for e in &m.evidence {
        match e.span {
            Some(s) => {
                let _ = writeln!(o, "  {:17}- {}  @{}", "", e.text, at(s));
            }
            None => {
                let _ = writeln!(o, "  {:17}- {}", "", e.text);
            }
        }
    }
}

fn anomalies(o: &mut String, list: &[Anomaly]) {
    let _ = writeln!(o);
    if list.is_empty() {
        let _ = writeln!(o, "Anomalies    none");
        return;
    }
    let _ = writeln!(o, "Anomalies    {}", list.len());
    for a in list {
        let _ = writeln!(o, "  {}", anomaly_line(a));
        if let Some(os) = &a.os_behaviour {
            let _ = writeln!(o, "  {:10}OS: {os}", "");
        }
    }
}

/// One-line description of an anomaly.
pub fn anomaly_line(a: &Anomaly) -> String {
    let sev = match a.severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    };
    let mut line = format!("{sev:<8}  {}  [{}]", a.message, a.code);
    if let Some(s) = a.span {
        let _ = write!(line, "  @{}", at(s));
    }
    line
}

pub(crate) fn row(o: &mut String, label: &str, value: &str, span: Option<Span>) {
    match span {
        Some(s) => {
            let _ = writeln!(o, "{label:LABEL$}{value:<44} @{}", at(s));
        }
        None => {
            let _ = writeln!(o, "{label:LABEL$}{value}");
        }
    }
}

/// `0x10` for a 1-byte span, `0x10..0x17` otherwise (inclusive end).
pub(crate) fn at(s: Span) -> String {
    match s.last() {
        Some(last) if s.len > 1 => format!("{:#x}..{:#x}", s.offset.0, last.0),
        _ => format!("{:#x}", s.offset.0),
    }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn sections_summary(o: &mut String, b: &LoadedBinary) {
    let Some(elf) = b.elf() else { return };
    let h = &elf.header;
    let _ = writeln!(o);
    if elf.section_headers.is_empty() {
        let _ = writeln!(
            o,
            "Sections         none (stripped or removed): symbols come from the dynamic segment"
        );
    } else {
        let names = match elf
            .shstrndx
            .and_then(|i| elf.section_headers.get(i as usize))
        {
            Some(t) => format!("names from section #{} {}", t.index, t.name_str()),
            None => "names unavailable".to_string(),
        };
        let _ = writeln!(
            o,
            "Sections         {} headers at offset {:#x}, {} bytes each ({names})",
            elf.shnum, h.e_shoff.value, h.e_shentsize.value
        );
    }
    let count = |t: SymbolTable| b.symbols.iter().filter(|s| s.table == t).count();
    let source = match elf.dynsym.as_ref().map(|t| t.source) {
        Some(fg_service::loader::elf::TableSource::DynamicSegment) => " (via the dynamic segment)",
        Some(_) => " (via section headers)",
        None => "",
    };
    let _ = writeln!(
        o,
        "Symbols          dynamic {}{source}, static {}{}; {} imports, {} exports",
        count(SymbolTable::Dynamic),
        count(SymbolTable::Static),
        if b.is_stripped() { " (stripped)" } else { "" },
        b.imports().count(),
        b.exports().count()
    );
    let tables: Vec<String> = elf
        .relocations
        .iter()
        .map(|t| format!("{} {}", t.name, t.entries.len()))
        .collect();
    if tables.is_empty() {
        let _ = writeln!(o, "Relocations      none");
    } else {
        let slots = b
            .relocations
            .iter()
            .filter(|r| matches!(r.kind, RelocKind::GotEntry | RelocKind::PltSlot))
            .count();
        let _ = writeln!(
            o,
            "Relocations      {} ({}); {slots} GOT/PLT slots (`fulg relocs`)",
            b.relocations.len(),
            tables.join(", ")
        );
    }
    let _ = writeln!(
        o,
        "Notes            {}",
        if elf.notes.is_empty() {
            "none".to_string()
        } else {
            format!("{} (`fulg notes`)", elf.notes.len())
        }
    );
    let _ = writeln!(o, "Code seeds       {} (`fulg seeds`)", b.seeds.len());
}

/// `fulg sections`: every section with its segment cross-check.
pub fn sections(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    if let Some(pe) = b.pe() {
        crate::render_pe::sections(&mut o, pe);
        return o;
    }
    let Some(elf) = b.elf() else {
        let _ = writeln!(o, "no section data");
        return o;
    };
    if elf.section_headers.is_empty() {
        let _ = writeln!(
            o,
            "No section headers: stripped or removed. The OS never reads them; see `fulg info` for segments."
        );
        return o;
    }
    let machine = elf.header.e_machine.value;
    let osabi = elf.header.ident.osabi.value;
    let _ = writeln!(
        o,
        "  {:>4}  {:<24} {:<14} {:<18} {:<10} {:<10} {:>2} {:<6} {:>3} {:>4} {:>3}  {:<10} Defined at",
        "#",
        "Name",
        "Type",
        "Address",
        "Offset",
        "Size",
        "ES",
        "Flags",
        "Lk",
        "Inf",
        "Al",
        "Segment"
    );
    for s in &elf.section_headers {
        let ty = consts::sh_type_name(s.sh_type.value, machine)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{:#x}", s.sh_type.value));
        // readelf's letters. `o`, `p` and `x` do not say which bit was set, so the
        // raw value is added at the end of the row.
        let flags = consts::sh_flags_letters(s.sh_flags.value, machine, osabi);
        let raw = if flags.contains(['o', 'p', 'x']) {
            format!("  flags {:#x}", s.sh_flags.value)
        } else {
            String::new()
        };
        let segment = if s.is_alloc() && s.sh_size.value > 0 {
            b.segments
                .iter()
                .find(|g| g.contains(fg_service::core::Va(s.sh_addr.value)))
                .map_or_else(|| "none!".to_string(), |g| g.name.clone())
        } else {
            "-".to_string()
        };
        let _ = writeln!(
            o,
            "  {:>4}  {:<24} {:<14} {:#018x} {:#010x} {:#010x} {:>2x} {:<6} {:>3} {:>4} {:>3}  {:<10} @{:#x}{}",
            s.index,
            s.name_str(),
            ty,
            s.sh_addr.value,
            s.sh_offset.value,
            s.sh_size.value,
            s.sh_entsize.value,
            flags,
            s.sh_link.value,
            s.sh_info.value,
            s.sh_addralign.value,
            segment,
            s.span.offset.0,
            raw
        );
    }
    let _ = writeln!(
        o,
        "\nFlags: W write, A alloc (loaded), X execute, M merge, S strings, I info link, L link order,"
    );
    let _ = writeln!(
        o,
        "       O extra OS processing required, G group, T TLS, C compressed, E exclude,"
    );
    let _ = writeln!(
        o,
        "       R retain (GNU, FreeBSD), D mbind, l large (x86-64), y pure code (ARM), v VLE (PowerPC),"
    );
    let _ = writeln!(
        o,
        "       o OS-specific, p processor-specific, x unknown (the raw value ends the row)"
    );
    o
}

pub(crate) fn kind_name(k: SymbolKind) -> &'static str {
    match k {
        SymbolKind::NoType => "NOTYPE",
        SymbolKind::Object => "OBJECT",
        SymbolKind::Function => "FUNC",
        SymbolKind::Section => "SECTION",
        SymbolKind::File => "FILE",
        SymbolKind::Common => "COMMON",
        SymbolKind::Tls => "TLS",
        SymbolKind::IndirectFunction => "IFUNC",
        _ => "OTHER",
    }
}

fn binding_name(b: SymbolBinding) -> &'static str {
    match b {
        SymbolBinding::Local => "LOCAL",
        SymbolBinding::Global => "GLOBAL",
        SymbolBinding::Weak => "WEAK",
        SymbolBinding::Unique => "UNIQUE",
        _ => "OTHER",
    }
}

/// `fulg symbols`: one line per symbol.
pub fn symbols(session: &Session, chosen: &[&Symbol]) -> String {
    let b = session.binary();
    let mut o = String::new();
    if b.symbols.is_empty() {
        let _ = writeln!(
            o,
            "No symbol tables found (fully stripped static binary, or no dynamic segment)."
        );
        return o;
    }
    let elf = b.elf();
    let ndx = |s: &Symbol| -> String {
        let t = match s.table {
            SymbolTable::Dynamic => elf.and_then(|e| e.dynsym.as_ref()),
            SymbolTable::Static => elf.and_then(|e| e.symtab.as_ref()),
            // PE: the ordinal, or the COFF section number.
            SymbolTable::Coff => {
                return b
                    .pe()
                    .and_then(|p| p.coff_symbols.iter().find(|c| c.index == s.index))
                    .map_or_else(|| "?".into(), |c| c.section_number.value.to_string());
            }
            _ => return s.ordinal.map_or_else(|| "-".into(), |o| format!("#{o}")),
        };
        t.and_then(|t| t.symbols.get(s.index as usize))
            .map_or_else(|| "?".into(), |e| e.ndx_display())
    };
    let _ = writeln!(
        o,
        "  {:<8} {:>6}  {:<18} {:>8}  {:<7} {:<7} {:>5}  {:<40} Defined at",
        "Table", "#", "Value", "Size", "Type", "Bind", "Ndx", "Name"
    );
    for s in chosen {
        let table = table_name(s.table);
        let _ = writeln!(
            o,
            "  {:<8} {:>6}  {:#018x} {:>8}  {:<7} {:<7} {:>5}  {:<40} @{:#x}",
            table,
            s.index,
            s.va.0,
            s.size,
            kind_name(s.kind),
            binding_name(s.binding),
            ndx(s),
            s.display_name(),
            s.defined_by.offset.0
        );
    }
    let _ = writeln!(
        o,
        "\n{} symbol(s) shown of {}",
        chosen.len(),
        b.symbols.len()
    );
    o
}

fn table_name(t: SymbolTable) -> &'static str {
    match t {
        SymbolTable::Dynamic => ".dynsym",
        SymbolTable::Static => ".symtab",
        SymbolTable::Imports => "import",
        SymbolTable::DelayImports => "delay",
        SymbolTable::Exports => "export",
        SymbolTable::Coff => "coff",
        _ => "?",
    }
}

fn reloc_kind_name(k: RelocKind) -> &'static str {
    match k {
        RelocKind::None => "none",
        RelocKind::Relative => "relative",
        RelocKind::Absolute => "absolute",
        RelocKind::GotEntry => "GOT",
        RelocKind::PltSlot => "PLT slot",
        RelocKind::Copy => "copy",
        RelocKind::IndirectRelative => "IFUNC",
        RelocKind::Tls => "TLS",
        _ => "other",
    }
}

/// `fulg relocs`: one line per relocation, grouped by table.
pub fn relocs(session: &Session, chosen: &[&Relocation]) -> String {
    let b = session.binary();
    let mut o = String::new();
    if b.pe().is_some() {
        pe_relocs(&mut o, b, chosen);
        return o;
    }
    let Some(elf) = b.elf() else {
        return o;
    };
    if elf.relocations.is_empty() {
        let _ = writeln!(o, "No relocation tables.");
        return o;
    }
    for t in &elf.relocations {
        let rows: Vec<&&Relocation> = chosen.iter().filter(|r| r.table == t.name).collect();
        let how = match t.source {
            fg_service::loader::elf::RelocSource::Dynamic(_) => "via the dynamic segment",
            _ => "via its section header",
        };
        let format = match t.format {
            RelocFormat::Rel => "REL",
            RelocFormat::Rela => "RELA",
            RelocFormat::Relr => "RELR",
            _ => "?",
        };
        let packed = if t.format == RelocFormat::Relr {
            format!(", packed in {} words", t.relr_words)
        } else {
            String::new()
        };
        let _ = writeln!(
            o,
            "{}  {format}, {} entries{packed}, {how}  @{}",
            t.name,
            t.entries.len(),
            at(t.file_range)
        );
        if rows.is_empty() {
            let _ = writeln!(o, "  (none shown)\n");
            continue;
        }
        let _ = writeln!(
            o,
            "  {:<18} {:<24} {:<9} {:<44} {:<18} Defined at",
            "Offset", "Type", "Kind", "Symbol + addend", "Stored value"
        );
        for r in rows {
            let ty = r
                .type_name
                .map_or_else(|| format!("type {}", r.r_type), str::to_string);
            let mut target = r.symbol_name.clone().unwrap_or_default();
            match r.addend {
                Some(a) if target.is_empty() => target = format!("{a:#x}"),
                Some(a) if a < 0 => target = format!("{target} - {:#x}", a.unsigned_abs()),
                Some(a) => target = format!("{target} + {a:#x}"),
                None => {}
            }
            let stored = r
                .stored_value
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| format!("{:#x}", v.value));
            let place = match (r.va, r.section) {
                (Some(v), _) => format!("{:#018x}", v.0),
                (None, Some(s)) => format!("[{s}]+{:#x}", r.offset),
                _ => format!("{:#x}", r.offset),
            };
            let _ = writeln!(
                o,
                "  {:<18} {:<24} {:<9} {:<44} {:<18} @{:#x}",
                place,
                ty,
                reloc_kind_name(r.kind),
                target,
                stored,
                r.defined_by.offset.0
            );
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(o, "Kinds:");
    for k in [
        RelocKind::Relative,
        RelocKind::GotEntry,
        RelocKind::PltSlot,
        RelocKind::Copy,
        RelocKind::IndirectRelative,
    ] {
        let _ = writeln!(o, "  {:<9} {}", reloc_kind_name(k), k.meaning());
    }
    let _ = writeln!(
        o,
        "Stored value: what the file holds at that address before the loader patches it\n\
         (for a lazily bound PLT slot, the address of its PLT stub; for REL/RELR, the addend)."
    );
    o
}

fn pe_relocs(o: &mut String, b: &LoadedBinary, chosen: &[&Relocation]) {
    if b.relocations.is_empty() {
        let _ = writeln!(o, "No relocations and no imports.");
        return;
    }
    let mut tables: Vec<&str> = Vec::new();
    for r in &b.relocations {
        if !tables.contains(&r.table.as_str()) {
            tables.push(&r.table);
        }
    }
    for t in tables {
        let rows: Vec<&&Relocation> = chosen.iter().filter(|r| r.table == t).collect();
        let total = b.relocations.iter().filter(|r| r.table == t).count();
        let what = match t {
            "IAT" => "import address table slots, filled by the loader at startup",
            "delay IAT" => "delay-load slots, filled on the first call",
            _ => "addresses adjusted when the image is not loaded at its preferred base",
        };
        let _ = writeln!(o, "{t}  {total} entries: {what}");
        if rows.is_empty() {
            let _ = writeln!(o, "  (none shown)\n");
            continue;
        }
        let _ = writeln!(
            o,
            "  {:<18} {:<26} {:<9} {:<44} {:<18} Defined at",
            "Address", "Type", "Kind", "Symbol", "Stored value"
        );
        for r in rows {
            let ty = r
                .type_name
                .map_or_else(|| format!("type {}", r.r_type), str::to_string);
            let stored = r
                .stored_value
                .as_ref()
                .map_or_else(|| "-".to_string(), |v| format!("{:#x}", v.value));
            let _ = writeln!(
                o,
                "  {:#018x} {:<26} {:<9} {:<44} {:<18} @{:#x}",
                r.va.map_or(r.offset, |v| v.0),
                ty,
                reloc_kind_name(r.kind),
                r.symbol_name.clone().unwrap_or_default(),
                stored,
                r.defined_by.offset.0
            );
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(
        o,
        "Stored value: what the file holds there before loading (for an IAT slot, the name\n\
         reference it starts as; for a delay-load slot, the stub that resolves it)."
    );
}

/// `fulg seeds`: where code is declared to start.
pub fn seeds(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    if b.seeds.is_empty() {
        let _ = writeln!(
            o,
            "No code seeds (no entry point, no init arrays, no exception or TLS tables)."
        );
        return o;
    }
    let _ = writeln!(
        o,
        "  {:<18} {:<18} {:<20} {:<40} Defined at",
        "Address", "End", "Kind", "Symbol"
    );
    for s in &b.seeds {
        let end = s
            .end
            .map_or_else(|| "-".to_string(), |e| format!("{:#018x}", e.0));
        let name = b
            .symbols
            .iter()
            .find(|x| x.va == s.va && x.defined && !x.name.is_empty())
            .map_or_else(String::new, Symbol::display_name);
        let kind = format!("{:?}", s.kind);
        let _ = writeln!(
            o,
            "  {:#018x} {:<18} {:<20} {:<40} @{}",
            s.va.0,
            end,
            kind,
            name,
            at(s.defined_by)
        );
        if let Some(pe) = b.pe()
            && matches!(
                s.kind,
                SeedKind::ExceptionTable | SeedKind::ExceptionFragment
            )
            && let Some(n) = crate::render_pe::unwind_note(pe, s.defined_by.offset.0)
        {
            let _ = writeln!(o, "  {:18} {:18} {:20} ({n})", "", "", "");
        }
    }
    let _ = writeln!(o, "\n{} seed(s). Kinds:", b.seeds.len());
    let mut kinds: Vec<SeedKind> = Vec::new();
    for s in &b.seeds {
        if !kinds.contains(&s.kind) {
            kinds.push(s.kind);
        }
    }
    for k in kinds {
        let _ = writeln!(o, "  {:<20} {}", format!("{k:?}"), k.meaning());
    }
    o
}

/// `fulg imports`: what the program needs from libraries, grouped by library.
pub fn imports(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    if let Some(pe) = b.pe() {
        crate::render_pe::imports(&mut o, pe);
        return o;
    }
    let list: Vec<&Symbol> = b.imports().collect();
    if list.is_empty() {
        let _ = writeln!(
            o,
            "No imports (statically linked, or no dynamic symbol table)."
        );
        return o;
    }
    let mut groups: Vec<(String, Vec<&Symbol>)> = Vec::new();
    for s in list {
        let lib = s
            .version
            .as_ref()
            .and_then(|v| v.library.clone())
            .unwrap_or_else(|| "(any library: unversioned)".to_string());
        match groups.iter_mut().find(|(l, _)| *l == lib) {
            Some((_, v)) => v.push(s),
            None => groups.push((lib, vec![s])),
        }
    }
    let slot = |s: &Symbol| {
        b.relocations.iter().find(|r| {
            matches!(r.kind, RelocKind::GotEntry | RelocKind::PltSlot)
                && r.symbol
                    .is_some_and(|x| x.table == s.table && x.index == s.index)
        })
    };
    let _ = writeln!(
        o,
        "Libraries: {}\n",
        b.libraries
            .iter()
            .map(|l| l.value.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (lib, syms) in groups {
        let _ = writeln!(o, "{lib}  ({} imports)", syms.len());
        let _ = writeln!(
            o,
            "  {:<18} {:<9} {:<7} {:<44} Defined at",
            "Slot", "Kind", "Type", "Name"
        );
        for s in syms {
            let (addr, k) = slot(s).map_or_else(
                || ("-".to_string(), "-"),
                |r| {
                    (
                        format!("{:#018x}", r.va.map_or(r.offset, |v| v.0)),
                        reloc_kind_name(r.kind),
                    )
                },
            );
            let _ = writeln!(
                o,
                "  {:<18} {:<9} {:<7} {:<44} @{:#x}",
                addr,
                k,
                kind_name(s.kind),
                s.display_name(),
                s.defined_by.offset.0
            );
        }
        let _ = writeln!(o);
    }
    o
}

/// `fulg exports`: what the file provides to others.
pub fn exports(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    if let Some(pe) = b.pe() {
        crate::render_pe::exports(&mut o, b, pe);
        return o;
    }
    let list: Vec<&Symbol> = b.exports().collect();
    if list.is_empty() {
        let _ = writeln!(o, "No exports.");
        return o;
    }
    let _ = writeln!(
        o,
        "  {:<18} {:>8}  {:<7} {:<7} {:<44} Defined at",
        "Address", "Size", "Type", "Bind", "Name"
    );
    for s in &list {
        let _ = writeln!(
            o,
            "  {:#018x} {:>8}  {:<7} {:<7} {:<44} @{:#x}",
            s.va.0,
            s.size,
            kind_name(s.kind),
            binding_name(s.binding),
            s.display_name(),
            s.defined_by.offset.0
        );
    }
    let _ = writeln!(o, "\n{} export(s)", list.len());
    o
}

/// `fulg resources`: the PE resource tree's leaves.
pub fn resources(session: &Session) -> String {
    let mut o = String::new();
    match session.binary().pe() {
        Some(pe) => crate::render_pe::resources(&mut o, pe),
        None => {
            let _ = writeln!(o, "Only PE files have resources.");
        }
    }
    o
}

/// `fulg notes`: every note, decoded.
pub fn notes(session: &Session) -> String {
    let b = session.binary();
    let mut o = String::new();
    if let Some(pe) = b.pe() {
        crate::render_pe::notes(&mut o, pe);
        return o;
    }
    let Some(elf) = b.elf() else {
        return o;
    };
    if elf.notes.is_empty() {
        let _ = writeln!(o, "No notes.");
        return o;
    }
    for n in &elf.notes {
        let place = match n.source {
            NoteSource::Segment(i) => format!("PT_NOTE #{i}"),
            NoteSource::Section(i) => format!("section #{i}"),
            _ => "?".to_string(),
        };
        let section = n
            .section
            .and_then(|i| elf.section_headers.get(i as usize))
            .map_or_else(String::new, |s| format!(" {}", s.name_str()));
        let ty = match n.owner.value.as_str() {
            "GNU" => consts::gnu_note_type_name(n.n_type.value)
                .map_or_else(|| format!("type {:#x}", n.n_type.value), str::to_string),
            _ => format!("type {:#x}", n.n_type.value),
        };
        let _ = writeln!(
            o,
            "{}  {ty}  ({place}{section}, {} data bytes)  @{}",
            n.owner.value,
            n.desc.len,
            at(n.span)
        );
        match &n.content {
            NoteContent::BuildId(id) => {
                let _ = writeln!(o, "  Build ID      {id}  @{}", at(n.desc));
            }
            NoteContent::AbiTag { os, version } => {
                let _ = writeln!(
                    o,
                    "  ABI           {os}, kernel {version} or newer  @{}",
                    at(n.desc)
                );
            }
            NoteContent::Properties(props) => {
                for p in props {
                    let _ = writeln!(o, "  Property      {}  @{}", p.text, at(p.data));
                }
            }
            NoteContent::GoldVersion(v) => {
                let _ = writeln!(o, "  Linker        gold {v}");
            }
            NoteContent::Package(json) => {
                let _ = writeln!(o, "  Package       {json}");
            }
            NoteContent::GoBuildId(id) => {
                let _ = writeln!(o, "  Go build ID   {id}");
            }
            _ => {}
        }
    }
    o
}

/// `fulg functions`: one line per function.
pub fn xrefs(l: &fg_service::xrefs::XrefList) -> String {
    let mut o = String::new();
    let named = |va: fg_service::core::Va, name: &Option<String>| match name {
        Some(n) => format!("{:#x} {n}", va.0),
        None => format!("{:#x}", va.0),
    };
    if let Some(t) = l.target {
        let name = l
            .refs
            .iter()
            .find(|r| r.to == t)
            .and_then(|r| r.to_name.clone());
        let extent = match l.size {
            Some(n) => format!(" ({n} bytes: references anywhere inside)"),
            None => String::new(),
        };
        let _ = writeln!(
            o,
            "{} reference{} to {}{extent}",
            l.refs.len(),
            if l.refs.len() == 1 { "" } else { "s" },
            named(t, &name)
        );
    } else {
        let _ = writeln!(o, "{} references", l.refs.len());
    }
    if l.refs.is_empty() {
        return o;
    }
    let _ = writeln!(o, "  {:<40} {:<10} {:<40} How", "From", "Kind", "To");
    for r in &l.refs {
        let guess = if r.certain { "" } else { " (a guess)" };
        let _ = writeln!(
            o,
            "  {:<40} {:<10} {:<40} {}{guess}",
            named(r.from, &r.from_name),
            r.kind.name(),
            named(r.to, &r.to_name),
            r.via
        );
    }
    o
}

pub fn functions(f: &fg_service::functions::Functions) -> String {
    use fg_service::functions::FunctionInfo;
    let mut o = String::new();
    if f.functions.is_empty() {
        let _ = writeln!(o, "No functions found.");
        return o;
    }
    let _ = writeln!(
        o,
        "  {:<18} {:>8} {:>6}  {:<15} {:<14} Name / evidence",
        "Address", "Bytes", "Blocks", "Confidence", "Found by"
    );
    for x in &f.functions {
        let FunctionInfo {
            entry,
            name,
            blocks,
            code_bytes,
            confidence,
            bucket,
            found_by,
            evidence,
            unresolved_jumps,
            no_return,
            ..
        } = x;
        let label = match name {
            Some(n) => n.clone(),
            None => evidence.first().cloned().unwrap_or_default(),
        };
        let mut flag = String::new();
        if !no_return.is_empty() {
            flag += " [no return]";
        }
        if *unresolved_jumps {
            flag += " [unresolved jump]";
        }
        let _ = writeln!(
            o,
            "  {:#018x} {:>8} {:>6}  {:<15} {:<14} {label}{flag}",
            entry.0,
            code_bytes,
            blocks,
            // Rounded down: 0.9999 is not shown as a certain 1.00.
            format!("{:.2} {:?}", (confidence * 100.0).floor() / 100.0, bucket),
            found_by,
        );
    }
    let _ = writeln!(
        o,
        "\n{} functions, {} never return; {} code ranges are parts of another function \
         (split-off cold code)",
        f.functions.len(),
        f.functions
            .iter()
            .filter(|x| !x.no_return.is_empty())
            .count(),
        f.fragments.len()
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouping() {
        assert_eq!(group(0), "0");
        assert_eq!(group(1234), "1,234");
        assert_eq!(group(1234567), "1,234,567");
    }

    #[test]
    fn spans_show_inclusive_end() {
        assert_eq!(at(Span::new(0x10, 2)), "0x10..0x11");
        assert_eq!(at(Span::new(0x7, 1)), "0x7");
    }
}
