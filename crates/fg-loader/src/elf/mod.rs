// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! ELF loader.
//!
//! Supports ELF32 and ELF64 in both byte orders, so later architectures need no
//! loader changes. Loading follows what the Linux kernel and the dynamic linker
//! look at (program headers, then the dynamic segment); section headers are
//! advisory metadata, used for names and cross-checked against the segments.

pub mod consts;
mod dynamic;
mod ehframe;
mod fortify;
mod header;
mod note;
mod phdr;
mod reloc;
mod section;
mod strtab;
mod symtab;

pub use dynamic::{DynamicEntry, DynamicStrings};
pub use header::{ElfHeader, Ident};
pub use note::{ElfNote, GnuProperty, NoteContent, NoteSource};
pub use phdr::ProgramHeader;
pub use reloc::{ElfRelocTable, ElfRelocation, RelocFormat, RelocSource, kind_of as reloc_kind};
pub use section::SectionHeader;
pub use symtab::{ElfSymbol, ElfSymbolTable, TableSource};

use crate::LoadError;
use crate::mitigation::{self as mit, Mitigation, MitigationReport, Verdict};
use crate::model::{
    BinaryKind, Format, FormatMetadata, LoadOptions, LoadedBinary, RelocKind, Relocation, Seed,
    SeedKind, Segment, Symbol, SymbolRef, SymbolTable,
};
use consts::*;
use fg_core::{
    Anomaly, ArchId, Bitness, ByteView, Endian, Evidence, Field, FileOffset, Severity, Span, Va,
};
use serde::Serialize;

/// ELF-specific details kept alongside the neutral model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ElfInfo {
    /// The file header.
    pub header: ElfHeader,
    /// Real number of program headers (differs from `e_phnum` when `PN_XNUM` is used).
    pub phnum: u32,
    /// Where the count came from when `e_phnum == PN_XNUM` (section header 0's `sh_info`).
    pub phnum_extended: Option<Field<u32>>,
    /// All program headers that could be read, in table order.
    pub program_headers: Vec<ProgramHeader>,
    /// Program interpreter path from `PT_INTERP`.
    pub interpreter: Option<Field<String>>,
    /// Dynamic-section entries read through `PT_DYNAMIC`, excluding the `DT_NULL` terminator.
    pub dynamic: Vec<DynamicEntry>,
    /// Real number of section headers (differs from `e_shnum` when the escape is used).
    pub shnum: u64,
    /// Real index of the section-name string table, if valid.
    pub shstrndx: Option<u32>,
    /// All section headers that could be read, in table order.
    pub section_headers: Vec<SectionHeader>,
    /// The dynamic symbol table (`.dynsym`), found via the dynamic segment when possible.
    pub dynsym: Option<ElfSymbolTable>,
    /// The static symbol table (`.symtab`), found via the section headers.
    pub symtab: Option<ElfSymbolTable>,
    /// Libraries and search paths named by the dynamic section.
    pub strings: DynamicStrings,
    /// Relocation tables, dynamic-segment tables first.
    pub relocations: Vec<ElfRelocTable>,
    /// Notes from note segments, then from note sections no segment covers.
    pub notes: Vec<ElfNote>,
}

impl ElfInfo {
    /// Program headers of a given type.
    pub fn headers_of(&self, p_type: u32) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers
            .iter()
            .filter(move |p| p.p_type.value == p_type)
    }

    /// First dynamic entry with `tag`.
    pub fn dynamic_entry(&self, tag: i64) -> Option<&DynamicEntry> {
        self.dynamic.iter().find(|d| d.tag.value == tag)
    }

    /// The GNU property note the run time reads: the one `PT_GNU_PROPERTY` points
    /// at, else the first property note found.
    pub fn property_note(&self) -> Option<&ElfNote> {
        let is_prop =
            |n: &&ElfNote| n.owner.value == "GNU" && n.n_type.value == NT_GNU_PROPERTY_TYPE_0;
        let by_segment = self.headers_of(PT_GNU_PROPERTY).next().and_then(|p| {
            let r = p.file_range();
            self.notes
                .iter()
                .filter(is_prop)
                .find(|n| n.span.offset == r.offset)
        });
        by_segment.or_else(|| self.notes.iter().find(is_prop))
    }

    /// The build ID note, if present.
    pub fn build_id(&self) -> Option<(&ElfNote, &str)> {
        self.notes.iter().find_map(|n| match &n.content {
            NoteContent::BuildId(id) => Some((n, id.as_str())),
            _ => None,
        })
    }
}

/// True if `bytes` starts with the ELF magic `7f 45 4c 46`.
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(&ELFMAG)
}

/// Loads an ELF file.
pub fn load(bytes: &[u8], options: &LoadOptions) -> Result<LoadedBinary, LoadError> {
    let limits = options.limits;
    let mut anomalies = Vec::new();
    let raw = ByteView::new(bytes, Endian::Little);

    if !is_elf(bytes) {
        return Err(LoadError::NotRecognized {
            magic: bytes.iter().take(4).copied().collect(),
        });
    }
    if raw.len() < EI_NIDENT {
        return Err(malformed("file ends inside e_ident", anomalies));
    }

    // e_ident: class and byte order decide how everything else is read.
    let class = raw.u8(EI_CLASS).unwrap_or(0);
    let bitness = match class {
        ELFCLASS32 => Bitness::Bits32,
        ELFCLASS64 => Bitness::Bits64,
        other => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "elf.ident.class",
                    format!("invalid EI_CLASS {other}"),
                )
                .at(Span::new(EI_CLASS, 1))
                .os("Linux refuses to execute the file"),
            );
            return Err(malformed("invalid ELF class", anomalies));
        }
    };
    let data = raw.u8(EI_DATA).unwrap_or(0);
    let endian = match data {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        other => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "elf.ident.data",
                    format!("invalid EI_DATA {other}"),
                )
                .at(Span::new(EI_DATA, 1))
                .os("Linux refuses to execute the file"),
            );
            return Err(malformed("invalid ELF byte order", anomalies));
        }
    };
    let view = raw.with_endian(endian);

    let hsize = header::header_size(bitness);
    let header = match header::parse(&view, bitness) {
        Ok(h) => h,
        Err(_) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "elf.header.truncated",
                    format!(
                        "file is {} bytes but the ELF header needs {hsize}",
                        view.len()
                    ),
                )
                .at(Span::new(0, view.len())),
            );
            return Err(malformed("file ends inside the ELF header", anomalies));
        }
    };
    check_header(&header, hsize, &mut anomalies);

    // Program header table.
    let (phnum, phnum_extended) = program_header_count(&view, bitness, &header, &mut anomalies);
    let program_headers = read_program_headers(
        &view,
        bitness,
        &header,
        phnum,
        limits.max_program_headers,
        &mut anomalies,
    );

    let interpreter = read_interpreter(
        &view,
        &program_headers,
        limits.max_interp_len,
        &mut anomalies,
    );
    let dynamic = read_dynamic(
        &view,
        bitness,
        &program_headers,
        limits.max_dynamic_entries,
        &mut anomalies,
    );

    let sections = section::read_table(
        &view,
        bitness,
        &header,
        limits.max_sections,
        limits.max_name_len,
        &mut anomalies,
    );
    let (dynsym, symtab) = symtab::read_all(
        &view,
        bitness,
        &sections.headers,
        &program_headers,
        &dynamic,
        &limits,
        &mut anomalies,
    );
    let strings = dynamic::read_strings(
        &view,
        &program_headers,
        &dynamic,
        limits.max_name_len,
        &mut anomalies,
    );
    let relocations = reloc::read_all(
        &reloc::Ctx {
            view: &view,
            bitness,
            machine: header.e_machine.value,
            relocatable: header.e_type.value == ET_REL,
            phdrs: &program_headers,
            load_map: &phdr::LoadMap::new(&program_headers),
            sections: &sections.headers,
            dynamic: &dynamic,
            dynsym_len: dynsym.as_ref().map(|t| t.symbols.len()),
            symtab_len: symtab.as_ref().map(|t| t.symbols.len()),
            limits: &limits,
        },
        &mut anomalies,
    );
    let notes = note::read_all(
        &note::Ctx {
            view: &view,
            bitness,
            machine: header.e_machine.value,
            phdrs: &program_headers,
            sections: &sections.headers,
            max_notes: limits.max_notes,
        },
        &mut anomalies,
    );

    let info = ElfInfo {
        header,
        phnum,
        phnum_extended,
        program_headers,
        interpreter,
        dynamic,
        shnum: sections.count,
        shstrndx: sections.shstrndx,
        section_headers: sections.headers,
        dynsym,
        symtab,
        strings,
        relocations,
        notes,
    };

    check_segments(&info, view.len(), &mut anomalies);
    section::check_against_segments(
        &info.section_headers,
        &info.program_headers,
        view.len(),
        &mut anomalies,
    );
    if info.section_headers.is_empty() && matches!(info.header.e_type.value, ET_EXEC | ET_DYN) {
        anomalies.push(Anomaly::new(
            Severity::Info,
            "elf.section.none",
            "no section headers (stripped or removed); symbols come from the dynamic segment",
        ));
    }

    let arch = arch_of(info.header.e_machine.value);
    if arch == ArchId::Unknown {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "elf.machine.unknown",
                format!("machine {} is not recognised", info.header.e_machine.value),
            )
            .at(info.header.e_machine.span),
        );
    }

    let (kind, kind_evidence) = classify(&info);
    let entry = entry_point(&info, kind);
    let segments = load_segments(&info);
    check_entry(entry.as_ref(), kind, &segments, &mut anomalies);
    let sections_neutral = neutral_sections(&info);
    let mut symbols = Vec::new();
    for t in [&info.dynsym, &info.symtab].into_iter().flatten() {
        let mut neutral = t.to_neutral();
        // Section symbols are unnamed; tools show the name of the section they mark.
        for (n, raw) in neutral.iter_mut().zip(&t.symbols) {
            if n.kind == crate::model::SymbolKind::Section
                && n.name.is_empty()
                && let Some(sec) = info.section_headers.get(usize::from(raw.st_shndx.value))
            {
                n.name = sec.name_str().to_string();
            }
        }
        symbols.extend(neutral);
    }

    let relocations = neutral_relocations(&info, &symbols);
    let mut seeds = neutral_seeds(
        &view,
        &info,
        bitness,
        kind,
        entry.as_ref(),
        &segments,
        &relocations,
    );
    if !matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        let eh = ehframe::read(&view, &info, bitness.word_size(), &segments, &mut anomalies);
        seeds.extend(eh.seeds);
    }
    let libraries = info.strings.needed.clone();
    let build_id = info
        .build_id()
        .map(|(n, id)| Field::new(id.to_string(), n.desc));
    check_properties(&info, &mut anomalies);

    let mitigations = MitigationReport::new(
        pie_verdict(kind, kind_evidence, &segments),
        nx_verdict(&info, kind),
        relro_verdict(&info, kind, &relocations),
        canary_verdict(&info, kind, &symbols),
        fortify_verdict(kind, &symbols),
    )
    .with_cfi(cfi_verdict(&info, kind))
    .with_separate_code(separate_code_verdict(&info, kind))
    .with_library_paths(library_paths_verdict(&info, kind));

    anomalies.sort_by_key(|a| std::cmp::Reverse(a.severity)); // stable: keeps file order within a severity
    Ok(LoadedBinary {
        format: Format::Elf,
        arch,
        bitness,
        endian,
        kind,
        entry,
        file_size: view.len(),
        segments,
        sections: sections_neutral,
        symbols,
        relocations,
        libraries,
        build_id,
        seeds,
        mitigations,
        anomalies,
        metadata: FormatMetadata::Elf(Box::new(info)),
    })
}

fn malformed(reason: &str, anomalies: Vec<Anomaly>) -> LoadError {
    LoadError::Malformed {
        reason: reason.to_string(),
        anomalies,
    }
}

fn arch_of(machine: u16) -> ArchId {
    match machine {
        EM_386 => ArchId::X86,
        EM_X86_64 => ArchId::X86_64,
        EM_ARM => ArchId::Arm,
        EM_AARCH64 => ArchId::Aarch64,
        EM_RISCV => ArchId::RiscV,
        _ => ArchId::Unknown,
    }
}

fn check_header(h: &ElfHeader, hsize: u64, anomalies: &mut Vec<Anomaly>) {
    if h.ident.version.value != 1 {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.ident.version",
                format!("EI_VERSION is {}, expected 1", h.ident.version.value),
            )
            .at(h.ident.version.span),
        );
    }
    if h.e_version.value != EV_CURRENT {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.header.version",
                format!("e_version is {}, expected 1", h.e_version.value),
            )
            .at(h.e_version.span),
        );
    }
    if u64::from(h.e_ehsize.value) != hsize {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.header.ehsize",
                format!("e_ehsize is {}, expected {hsize}", h.e_ehsize.value),
            )
            .at(h.e_ehsize.span),
        );
    }
}

/// Real program-header count, resolving the `PN_XNUM` escape.
fn program_header_count(
    view: &ByteView<'_>,
    bitness: Bitness,
    h: &ElfHeader,
    anomalies: &mut Vec<Anomaly>,
) -> (u32, Option<Field<u32>>) {
    if h.e_phnum.value != PN_XNUM {
        return (u32::from(h.e_phnum.value), None);
    }
    match header::section0_info(view, bitness, h.e_shoff.value) {
        Ok(info) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "elf.phdr.extended_count",
                    format!(
                        "e_phnum is PN_XNUM; the real count {} comes from section header 0",
                        info.value
                    ),
                )
                .at(info.span),
            );
            (info.value, Some(info))
        }
        Err(_) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "elf.phdr.extended_count_unreadable",
                    "e_phnum is PN_XNUM but section header 0 is outside the file",
                )
                .at(h.e_phnum.span),
            );
            (0, None)
        }
    }
}

fn read_program_headers(
    view: &ByteView<'_>,
    bitness: Bitness,
    h: &ElfHeader,
    phnum: u32,
    limit: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<ProgramHeader> {
    if phnum == 0 {
        return Vec::new();
    }
    let expected = phdr::entry_size(bitness);
    let stride = u64::from(h.e_phentsize.value);
    if stride < expected {
        anomalies.push(
            Anomaly::new(Severity::Error, "elf.phdr.entsize_too_small",
                format!("e_phentsize is {stride}, smaller than the {expected}-byte entry; program headers not read"))
            .at(h.e_phentsize.span)
            .os("Linux refuses to execute the file (e_phentsize must match exactly)"),
        );
        return Vec::new();
    }
    if stride != expected {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.phdr.entsize",
                format!(
                    "e_phentsize is {stride}, expected {expected}; reading with the declared stride"
                ),
            )
            .at(h.e_phentsize.span)
            .os("Linux refuses to execute the file (e_phentsize must match exactly)"),
        );
    }

    let mut count = phnum;
    if count > limit {
        anomalies.push(
            Anomaly::new(Severity::Error, "elf.phdr.limit",
                format!("{count} program headers exceeds the limit of {limit}; reading the first {limit}"))
            .at(h.e_phnum.span),
        );
        count = limit;
    }

    let table = Span::new(h.e_phoff.value, u64::from(count).saturating_mul(stride));
    if table.end().is_none() {
        anomalies.push(
            Anomaly::new(
                Severity::Error,
                "elf.phdr.table_overflow",
                "e_phoff + table size overflows a 64-bit offset",
            )
            .at(h.e_phoff.span),
        );
        return Vec::new();
    }

    let mut out = Vec::new();
    for i in 0..count {
        let base = h.e_phoff.value + u64::from(i) * stride; // cannot overflow: checked via table.end()
        match phdr::parse_one(view, bitness, i, base) {
            Ok(p) => out.push(p),
            Err(_) => {
                anomalies.push(
                    Anomaly::new(Severity::Error, "elf.phdr.table_truncated",
                        format!("program header table claims {count} entries but the file ends after {i}"))
                    .at(table)
                    .os("Linux refuses to execute the file"),
                );
                break;
            }
        }
    }
    out
}

fn read_interpreter(
    view: &ByteView<'_>,
    phdrs: &[ProgramHeader],
    max_len: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Option<Field<String>> {
    let mut interps = phdrs.iter().filter(|p| p.p_type.value == PT_INTERP);
    let first = interps.next()?;
    if interps.next().is_some() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.interp.multiple",
                "more than one PT_INTERP; using the first",
            )
            .at(first.span)
            .os("Linux rejects files with more than one PT_INTERP"),
        );
    }
    let limit = first.p_filesz.value.min(max_len);
    match view.cstr(first.p_offset.value, limit) {
        Ok(Some(s)) => Some(s.map(|b| String::from_utf8_lossy(b).into_owned())),
        Ok(None) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.interp.unterminated",
                    "PT_INTERP path has no NUL terminator within its segment",
                )
                .at(first.file_range()),
            );
            None
        }
        Err(_) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.interp.out_of_bounds",
                    "PT_INTERP points outside the file",
                )
                .at(first.span),
            );
            None
        }
    }
}

fn read_dynamic(
    view: &ByteView<'_>,
    bitness: Bitness,
    phdrs: &[ProgramHeader],
    limit: u32,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<DynamicEntry> {
    let mut dyns = phdrs.iter().filter(|p| p.p_type.value == PT_DYNAMIC);
    let Some(first) = dyns.next() else {
        return Vec::new();
    };
    if dyns.next().is_some() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.multiple",
                "more than one PT_DYNAMIC; using the first",
            )
            .at(first.span),
        );
    }
    let scan = dynamic::scan(
        view,
        bitness,
        first.p_offset.value,
        first.p_filesz.value,
        limit,
    );
    if scan.truncated {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.truncated",
                "dynamic section runs past the end of the file",
            )
            .at(first.file_range()),
        );
    } else if scan.hit_limit {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.limit",
                format!("dynamic section has more than {limit} entries; stopped reading"),
            )
            .at(first.file_range()),
        );
    } else if !scan.terminated {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.dynamic.unterminated",
                "dynamic section has no DT_NULL terminator",
            )
            .at(first.file_range()),
        );
    }
    scan.entries
}

fn check_segments(info: &ElfInfo, file_len: u64, anomalies: &mut Vec<Anomaly>) {
    let mut prev_load: Option<&ProgramHeader> = None;
    let loads: Vec<&ProgramHeader> = info.headers_of(PT_LOAD).collect();

    for p in &info.program_headers {
        let range = p.file_range();
        if p.p_type.value != PT_NULL
            && range.end().is_none_or(|e| e.0 > file_len)
            && p.p_filesz.value > 0
        {
            anomalies.push(
                Anomaly::new(Severity::Warning, "elf.segment.past_eof",
                    format!("program header #{} file range {}..+{:#x} extends past the end of the file ({file_len} bytes)",
                        p.index, range.offset, range.len))
                .at(p.span)
                .os("Linux maps it anyway; touching pages beyond the end of the file raises SIGBUS"),
            );
        }
        if p.p_type.value == PT_LOAD && p.p_filesz.value > p.p_memsz.value {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.segment.filesz_gt_memsz",
                    format!(
                        "LOAD #{}: p_filesz {:#x} is larger than p_memsz {:#x}",
                        p.index, p.p_filesz.value, p.p_memsz.value
                    ),
                )
                .at(p.p_filesz.span),
            );
        }
        let align = p.p_align.value;
        if p.p_type.value == PT_LOAD && align > 1 {
            if !align.is_power_of_two() {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "elf.segment.align",
                        format!(
                            "LOAD #{}: p_align {align:#x} is not a power of two",
                            p.index
                        ),
                    )
                    .at(p.p_align.span),
                );
            } else if p.p_vaddr.value % align != p.p_offset.value % align {
                anomalies.push(
                    Anomaly::new(Severity::Warning, "elf.segment.misaligned",
                        format!("LOAD #{}: p_vaddr and p_offset are not congruent modulo p_align {align:#x}", p.index))
                    .at(p.span),
                );
            }
        }
        if p.p_type.value == PT_LOAD && p.perms().is_wx() {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.segment.wx",
                    format!("LOAD #{} is both writable and executable", p.index),
                )
                .at(p.p_flags.span),
            );
        }
        if p.p_type.value == PT_LOAD {
            if let Some(prev) = prev_load
                && p.p_vaddr.value < prev.p_vaddr.value
            {
                anomalies.push(
                    Anomaly::new(Severity::Warning, "elf.segment.unsorted",
                        format!("LOAD #{} has a lower address than LOAD #{} (the ELF spec requires ascending order)",
                            p.index, prev.index))
                    .at(p.p_vaddr.span),
                );
            }
            prev_load = Some(p);
        }
    }

    for (i, a) in loads.iter().enumerate() {
        for b in &loads[i + 1..] {
            let (a0, a1) = (
                a.p_vaddr.value,
                a.p_vaddr.value.saturating_add(a.p_memsz.value),
            );
            let (b0, b1) = (
                b.p_vaddr.value,
                b.p_vaddr.value.saturating_add(b.p_memsz.value),
            );
            if a0 < b1 && b0 < a1 && a.p_memsz.value > 0 && b.p_memsz.value > 0 {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "elf.segment.overlap",
                        format!("LOAD #{} and LOAD #{} overlap in memory", a.index, b.index),
                    )
                    .at(b.p_vaddr.span),
                );
            }
        }
    }
}

/// Decides the file kind, returning the evidence used.
fn classify(info: &ElfInfo) -> (BinaryKind, Vec<Evidence>) {
    let t = &info.header.e_type;
    let type_ev = Evidence::at(
        format!("e_type = ET_{} ({})", e_type_name(t.value), t.value),
        t.span,
    );
    match t.value {
        ET_REL => (BinaryKind::Relocatable, vec![type_ev]),
        ET_EXEC => (BinaryKind::Executable, vec![type_ev]),
        ET_CORE => (BinaryKind::Core, vec![type_ev]),
        ET_DYN => {
            if let Some(f1) = info.dynamic_entry(DT_FLAGS_1)
                && f1.value.value & DF_1_PIE != 0
            {
                return (
                    BinaryKind::PieExecutable,
                    vec![
                        type_ev,
                        Evidence::at(
                            format!("DT_FLAGS_1 = {:#x} includes DF_1_PIE", f1.value.value),
                            f1.value.span,
                        ),
                    ],
                );
            }
            if let Some(interp) = &info.interpreter {
                return (
                    BinaryKind::PieExecutable,
                    vec![
                        type_ev,
                        Evidence::at(
                            format!(
                                "has a program interpreter ({}) but no DF_1_PIE flag: inferred to be \
                        a PIE (older linkers did not set DF_1_PIE; runnable libraries such as libc also have \
                        an interpreter)",
                                interp.value
                            ),
                            interp.span,
                        ),
                    ],
                );
            }
            (
                BinaryKind::SharedObject,
                vec![
                    type_ev,
                    Evidence::new("no DF_1_PIE flag and no program interpreter"),
                ],
            )
        }
        _ => (BinaryKind::Unknown, vec![type_ev]),
    }
}

fn entry_point(info: &ElfInfo, kind: BinaryKind) -> Option<Field<Va>> {
    let e = &info.header.e_entry;
    let has_entry =
        e.value != 0 || matches!(kind, BinaryKind::Executable | BinaryKind::PieExecutable);
    has_entry.then(|| e.clone().map(Va))
}

fn load_segments(info: &ElfInfo) -> Vec<Segment> {
    info.headers_of(PT_LOAD)
        .map(|p| {
            Segment::new(
                format!("LOAD #{}", p.index),
                Va(p.p_vaddr.value),
                p.p_memsz.value,
                FileOffset(p.p_offset.value),
                p.p_filesz.value,
                p.perms(),
                p.span,
            )
        })
        .collect()
}

fn check_entry(
    entry: Option<&Field<Va>>,
    kind: BinaryKind,
    segments: &[Segment],
    anomalies: &mut Vec<Anomaly>,
) {
    let Some(entry) = entry else { return };
    if !matches!(kind, BinaryKind::Executable | BinaryKind::PieExecutable) {
        return;
    }
    if !segments
        .iter()
        .any(|s| s.perms.execute && s.contains(entry.value))
    {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.entry.not_executable",
                format!(
                    "entry point {} is not inside any executable LOAD segment",
                    entry.value
                ),
            )
            .at(entry.span),
        );
    }
}

fn pie_verdict(kind: BinaryKind, kind_evidence: Vec<Evidence>, segments: &[Segment]) -> Mitigation {
    let (verdict, summary) = match kind {
        BinaryKind::PieExecutable => (
            Verdict::Enabled,
            "position-independent executable".to_string(),
        ),
        BinaryKind::Executable => {
            let base = segments.iter().map(|s| s.va.0).min();
            let summary = match base {
                Some(b) => format!("fixed load address (lowest LOAD segment at {b:#x})"),
                None => "fixed-address executable".to_string(),
            };
            (Verdict::Disabled, summary)
        }
        BinaryKind::SharedObject => (
            Verdict::NotApplicable,
            "shared library: always position-independent".into(),
        ),
        _ => (
            Verdict::NotApplicable,
            format!("not applicable to a {}", kind.name()),
        ),
    };
    Mitigation::new("PIE", verdict, summary, kind_evidence, mit::WHY_PIE)
}

fn nx_verdict(info: &ElfInfo, kind: BinaryKind) -> Mitigation {
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return Mitigation::new(
            "NX",
            Verdict::NotApplicable,
            format!("not applicable to a {}", kind.name()),
            Vec::new(),
            mit::WHY_NX,
        );
    }
    let mut evidence = Vec::new();
    let verdict_summary = match info.headers_of(PT_GNU_STACK).next() {
        Some(p) => {
            let perms = p.perms();
            evidence.push(Evidence::at(
                format!("PT_GNU_STACK (program header #{}) flags {perms}", p.index),
                p.p_flags.span,
            ));
            if perms.execute {
                (Verdict::Disabled, "stack is executable".to_string())
            } else {
                (Verdict::Enabled, "stack is not executable".to_string())
            }
        }
        None => {
            evidence.push(Evidence::new("no PT_GNU_STACK program header"));
            (Verdict::Unknown, "no PT_GNU_STACK: stack permissions fall back to the kernel and architecture \
                default (executable on older kernels and many architectures; checksec reports NX disabled)".into())
        }
    };
    for p in info.headers_of(PT_LOAD).filter(|p| p.perms().is_wx()) {
        evidence.push(Evidence::at(
            format!("note: LOAD #{} is writable and executable, so code can be injected there regardless", p.index),
            p.p_flags.span));
    }
    let (verdict, summary) = verdict_summary;
    Mitigation::new("NX", verdict, summary, evidence, mit::WHY_NX)
}

fn relro_verdict(info: &ElfInfo, kind: BinaryKind, relocs: &[Relocation]) -> Mitigation {
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return Mitigation::new(
            "RELRO",
            Verdict::NotApplicable,
            format!("not applicable to a {}", kind.name()),
            Vec::new(),
            mit::WHY_RELRO,
        );
    }
    let Some(relro) = info.headers_of(PT_GNU_RELRO).next() else {
        return Mitigation::new(
            "RELRO",
            Verdict::Disabled,
            "no RELRO",
            vec![Evidence::new("no PT_GNU_RELRO program header")],
            mit::WHY_RELRO,
        );
    };
    let mut evidence = vec![Evidence::at(
        format!(
            "PT_GNU_RELRO (program header #{}) covers {:#x} bytes at {:#x}",
            relro.index, relro.p_memsz.value, relro.p_vaddr.value
        ),
        relro.span,
    )];

    let mut bind_now = None;
    if let Some(d) = info.dynamic_entry(DT_BIND_NOW) {
        bind_now = Some(Evidence::at("DT_BIND_NOW present", d.tag.span));
    } else if let Some(d) = info
        .dynamic_entry(DT_FLAGS)
        .filter(|d| d.value.value & DF_BIND_NOW != 0)
    {
        bind_now = Some(Evidence::at(
            format!("DT_FLAGS = {:#x} includes DF_BIND_NOW", d.value.value),
            d.value.span,
        ));
    } else if let Some(d) = info
        .dynamic_entry(DT_FLAGS_1)
        .filter(|d| d.value.value & DF_1_NOW != 0)
    {
        bind_now = Some(Evidence::at(
            format!("DT_FLAGS_1 = {:#x} includes DF_1_NOW", d.value.value),
            d.value.span,
        ));
    }

    // Which GOT slots does the RELRO range actually protect?
    let (r0, r1) = (
        relro.p_vaddr.value,
        relro.p_vaddr.value.saturating_add(relro.p_memsz.value),
    );
    let slots: Vec<&Relocation> = relocs
        .iter()
        .filter(|r| matches!(r.kind, RelocKind::GotEntry | RelocKind::PltSlot))
        .collect();
    let outside: Vec<&&Relocation> = slots
        .iter()
        .filter(|r| r.va.is_some_and(|v| v.0 < r0 || v.0 >= r1))
        .collect();
    let lazy = slots
        .iter()
        .filter(|r| r.kind == RelocKind::PltSlot)
        .count();
    if !slots.is_empty() {
        evidence.push(Evidence::new(if outside.is_empty() {
            format!("all {} GOT/PLT slots lie inside the RELRO range", slots.len())
        } else {
            format!(
                "{} of {} GOT/PLT slots lie outside the RELRO range and stay writable (first: {} at {})",
                outside.len(),
                slots.len(),
                outside[0].symbol_name.as_deref().unwrap_or("?"),
                outside[0].va.map_or_else(String::new, |v| v.to_string())
            )
        }));
    }

    match bind_now {
        Some(ev) if !outside.is_empty() => {
            evidence.push(ev);
            Mitigation::new(
                "RELRO",
                Verdict::Partial,
                "BIND_NOW, but some GOT slots are outside the read-only range",
                evidence,
                mit::WHY_RELRO,
            )
        }
        Some(ev) => {
            evidence.push(ev);
            Mitigation::new(
                "RELRO",
                Verdict::Enabled,
                "full RELRO (GOT read-only after startup)",
                evidence,
                mit::WHY_RELRO,
            )
        }
        None => {
            evidence.push(Evidence::new(if info.dynamic.is_empty() {
                "no dynamic section, so there is no lazily bound GOT to protect".to_string()
            } else if lazy > 0 {
                format!(
                    "no BIND_NOW: {lazy} PLT slot(s) are bound lazily, so that part of the GOT stays writable"
                )
            } else {
                "no BIND_NOW: symbols are bound lazily, so the GOT stays writable".to_string()
            }));
            Mitigation::new(
                "RELRO",
                Verdict::Partial,
                "partial RELRO",
                evidence,
                mit::WHY_RELRO,
            )
        }
    }
}

fn neutral_sections(info: &ElfInfo) -> Vec<crate::model::Section> {
    info.section_headers
        .iter()
        .filter(|s| s.sh_type.value != SHT_NULL)
        .map(|s| {
            let f = s.sh_flags.value;
            crate::model::Section::new(
                s.name_str().to_string(),
                s.is_alloc().then_some(Va(s.sh_addr.value)),
                FileOffset(s.sh_offset.value),
                s.sh_size.value,
                s.file_range().len,
                fg_core::Perms::new(s.is_alloc(), f & SHF_WRITE != 0, f & SHF_EXECINSTR != 0),
                s.span,
            )
        })
        .collect()
}

fn table_label(s: &crate::model::Symbol) -> &'static str {
    match s.table {
        crate::model::SymbolTable::Dynamic => ".dynsym",
        _ => ".symtab",
    }
}

fn canary_verdict(
    info: &ElfInfo,
    kind: BinaryKind,
    symbols: &[crate::model::Symbol],
) -> Mitigation {
    if kind == BinaryKind::Core {
        return Mitigation::new(
            "Canary",
            Verdict::NotApplicable,
            "not applicable to a core dump",
            Vec::new(),
            mit::WHY_CANARY,
        );
    }
    if symbols.is_empty() {
        return Mitigation::new(
            "Canary",
            Verdict::Unknown,
            "no symbol tables to check; finding canaries in stripped code needs disassembly (a later milestone)",
            Vec::new(),
            mit::WHY_CANARY,
        );
    }
    const MARKERS: [&str; 3] = [
        "__stack_chk_fail",
        "__stack_chk_guard",
        "__stack_chk_fail_local",
    ];
    match symbols.iter().find(|s| MARKERS.contains(&s.base_name())) {
        Some(s) => {
            let mut evidence = vec![Evidence::at(
                format!(
                    "{} {} ({} #{})",
                    if s.defined { "defines" } else { "imports" },
                    s.display_name(),
                    table_label(s),
                    s.index
                ),
                s.defined_by,
            )];
            let summary = if s.defined && info.dynsym.as_ref().is_none_or(|t| t.symbols.len() <= 1)
            {
                evidence.push(Evidence::new("statically linked: libc's own canary code is linked in, so this \
                    proves libc was built with canaries, not necessarily the program's own functions"));
                "canary support linked in"
            } else {
                "stack canaries in use"
            };
            Mitigation::new(
                "Canary",
                Verdict::Enabled,
                summary,
                evidence,
                mit::WHY_CANARY,
            )
        }
        None => Mitigation::new(
            "Canary",
            Verdict::Disabled,
            "no canary: no function references __stack_chk_fail",
            vec![Evidence::new(format!(
                "searched {} symbols for __stack_chk_fail / __stack_chk_guard",
                symbols.len()
            ))],
            mit::WHY_CANARY,
        ),
    }
}

fn fortify_verdict(kind: BinaryKind, symbols: &[crate::model::Symbol]) -> Mitigation {
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return Mitigation::new(
            "FORTIFY",
            Verdict::NotApplicable,
            format!("not applicable to a {}", kind.name()),
            Vec::new(),
            mit::WHY_FORTIFY,
        );
    }
    let imports: Vec<&crate::model::Symbol> = symbols.iter().filter(|s| s.is_import()).collect();
    if imports.is_empty() {
        let (verdict, summary) = if symbols.is_empty() {
            (Verdict::Unknown, "no symbol tables to check")
        } else {
            (
                Verdict::NotApplicable,
                "no imported libc functions (statically linked): fortified calls are \
                resolved inside the binary and need disassembly to find",
            )
        };
        return Mitigation::new("FORTIFY", verdict, summary, Vec::new(), mit::WHY_FORTIFY);
    }
    let mut fortified: Vec<&crate::model::Symbol> = Vec::new();
    let mut plain: Vec<&crate::model::Symbol> = Vec::new();
    for s in &imports {
        if fortify::fortified_base(s.base_name()).is_some() {
            if !fortified.iter().any(|f| f.base_name() == s.base_name()) {
                fortified.push(s);
            }
        } else if fortify::is_fortifiable(s.base_name())
            && !plain.iter().any(|f| f.base_name() == s.base_name())
        {
            plain.push(s);
        }
    }
    // Counted per function: `memcpy` is protected if `__memcpy_chk` is used anywhere.
    // A plain `memcpy` import as well means some calls still skip the check.
    let (partial, never): (Vec<_>, Vec<_>) = plain.into_iter().partition(|p| {
        fortified
            .iter()
            .any(|f| fortify::fortified_base(f.base_name()) == Some(p.base_name()))
    });
    let mut evidence: Vec<Evidence> = fortified
        .iter()
        .map(|s| {
            Evidence::at(
                format!("imports {} (fortified)", s.display_name()),
                s.defined_by,
            )
        })
        .collect();
    evidence.extend(partial.iter().map(|s| {
        Evidence::at(
            format!(
                "imports {} (fortified elsewhere, also called without checks)",
                s.display_name()
            ),
            s.defined_by,
        )
    }));
    evidence.extend(never.iter().map(|s| {
        Evidence::at(
            format!(
                "imports {} (fortifiable, never fortified)",
                s.display_name()
            ),
            s.defined_by,
        )
    }));
    let total = fortified.len() + never.len();
    let unchecked = if partial.is_empty() {
        String::new()
    } else {
        format!("; {} of them also called without checks", partial.len())
    };
    let (verdict, summary) = match (fortified.len(), never.len()) {
        (0, 0) => (
            Verdict::NotApplicable,
            "no fortifiable libc functions imported".to_string(),
        ),
        (0, _) => (
            Verdict::Disabled,
            format!("not fortified: 0 of {total} fortifiable functions use a _chk variant"),
        ),
        (n, 0) => (
            Verdict::Enabled,
            format!("fortified: all {n} fortifiable functions use _chk variants{unchecked}"),
        ),
        (n, _) => (
            Verdict::Enabled,
            format!("fortified: {n} of {total} fortifiable functions use _chk variants{unchecked}"),
        ),
    };
    Mitigation::new("FORTIFY", verdict, summary, evidence, mit::WHY_FORTIFY)
}

/// Converts relocation tables to the neutral model, naming each symbol.
fn neutral_relocations(info: &ElfInfo, symbols: &[Symbol]) -> Vec<Relocation> {
    let machine = info.header.e_machine.value;
    let relocatable = info.header.e_type.value == ET_REL;
    // Neutral symbols are each table's entries in order, dynamic table first.
    let dyn_len = symbols
        .iter()
        .take_while(|s| s.table == SymbolTable::Dynamic)
        .count();
    let lookup = |r: SymbolRef| -> Option<&Symbol> {
        let base = match r.table {
            SymbolTable::Dynamic => 0,
            _ => dyn_len,
        };
        symbols
            .get(base + r.index as usize)
            .filter(|s| s.table == r.table && s.index == r.index)
    };
    let mut out = Vec::new();
    for t in &info.relocations {
        for e in &t.entries {
            let symbol = t
                .symbols
                .filter(|_| e.r_sym != 0)
                .map(|tab| SymbolRef::new(tab, e.r_sym));
            out.push(Relocation {
                table: t.name.clone(),
                offset: e.r_offset.value,
                va: (!relocatable).then_some(Va(e.r_offset.value)),
                section: if relocatable { t.applies_to } else { None },
                r_type: e.r_type,
                type_name: r_type_name(machine, e.r_type),
                kind: reloc::kind_of(machine, e.r_type),
                symbol,
                symbol_name: symbol.and_then(lookup).map(Symbol::display_name),
                addend: e.r_addend.as_ref().map(|a| a.value),
                stored_value: e.stored.clone(),
                defined_by: e.span,
                applied_at_load: t.applied_at_load,
            });
        }
    }
    out
}

/// Most entries read from one init/fini array.
const MAX_ARRAY_SEEDS: u64 = 1 << 16;

/// Code start addresses the file declares: the entry point, `DT_INIT` /
/// `DT_FINI`, and the init / fini / preinit arrays (found through the dynamic
/// segment, else through their section headers). Array slots that a relocation
/// fills are read from the relocation, the way the dynamic linker sees them.
fn neutral_seeds(
    view: &ByteView<'_>,
    info: &ElfInfo,
    bitness: Bitness,
    kind: BinaryKind,
    entry: Option<&Field<Va>>,
    segments: &[Segment],
    relocs: &[Relocation],
) -> Vec<Seed> {
    let mut out = Vec::new();
    if let Some(e) = entry {
        out.push(Seed::new(e.value, None, SeedKind::Entry, e.span));
    }
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return out;
    }
    for (tag, k) in [(DT_INIT, SeedKind::Init), (DT_FINI, SeedKind::Fini)] {
        if let Some(d) = info.dynamic_entry(tag).filter(|d| d.value.value != 0) {
            out.push(Seed::new(Va(d.value.value), None, k, d.value.span));
        }
    }
    let by_place: std::collections::HashMap<u64, &Relocation> = relocs
        .iter()
        .filter_map(|r| r.va.map(|v| (v.0, r)))
        .collect();
    let w = bitness.word_size();
    for (addr_tag, size_tag, sh_type, k) in [
        (
            DT_PREINIT_ARRAY,
            DT_PREINIT_ARRAYSZ,
            SHT_PREINIT_ARRAY,
            SeedKind::PreinitArray,
        ),
        (
            DT_INIT_ARRAY,
            DT_INIT_ARRAYSZ,
            SHT_INIT_ARRAY,
            SeedKind::InitArray,
        ),
        (
            DT_FINI_ARRAY,
            DT_FINI_ARRAYSZ,
            SHT_FINI_ARRAY,
            SeedKind::FiniArray,
        ),
    ] {
        let from_dynamic = info
            .dynamic_entry(addr_tag)
            .zip(info.dynamic_entry(size_tag))
            .map(|(a, s)| (a.value.value, s.value.value));
        let from_section = || {
            info.section_headers
                .iter()
                .find(|s| s.sh_type.value == sh_type && s.is_alloc())
                .map(|s| (s.sh_addr.value, s.sh_size.value))
        };
        let Some((addr, size)) = from_dynamic.or_else(from_section) else {
            continue;
        };
        for i in 0..(size / u64::from(w)).min(MAX_ARRAY_SEEDS) {
            let place = addr.wrapping_add(i * u64::from(w));
            let slot = segments
                .iter()
                .find_map(|s| s.file_offset_of(Va(place)))
                .and_then(|o| view.field_uint(o.0, w).ok());
            let (target, span) = match by_place.get(&place) {
                Some(r) if r.kind == RelocKind::Relative && r.addend.is_some() => {
                    (r.addend.unwrap_or(0) as u64, r.defined_by)
                }
                _ => match &slot {
                    Some(f) => (f.value, f.span),
                    None => continue,
                },
            };
            // 0 and -1 are placeholders, not functions.
            let all_ones = if w == 8 {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            };
            if target == 0 || target == all_ones {
                continue;
            }
            let span = slot.as_ref().map_or(span, |f| f.span);
            out.push(Seed::new(Va(target), None, k, span));
        }
    }
    out
}

/// Cross-checks the property note against `PT_GNU_PROPERTY`.
fn check_properties(info: &ElfInfo, anomalies: &mut Vec<Anomaly>) {
    let props: Vec<&ElfNote> = info
        .notes
        .iter()
        .filter(|n| n.owner.value == "GNU" && n.n_type.value == NT_GNU_PROPERTY_TYPE_0)
        .collect();
    if props.len() > 1 {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "elf.property.multiple",
                format!(
                    "{} GNU property notes; the run time reads only one",
                    props.len()
                ),
            )
            .at(props[1].span),
        );
    }
    if let Some(p) = info.headers_of(PT_GNU_PROPERTY).next() {
        let r = p.file_range();
        if !props.iter().any(|n| n.span.offset == r.offset) {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "elf.property.segment_mismatch",
                    format!(
                        "PT_GNU_PROPERTY (program header #{}) does not point at a GNU property note",
                        p.index
                    ),
                )
                .at(p.span),
            );
        }
    } else if !props.is_empty()
        && info.header.e_machine.value == EM_AARCH64
        && matches!(info.header.e_type.value, ET_EXEC | ET_DYN)
    {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "elf.property.no_segment",
                "GNU property note without a PT_GNU_PROPERTY program header",
            )
            .at(props[0].span)
            .os(
                "Linux on AArch64 reads BTI marking only through PT_GNU_PROPERTY, so BTI stays off",
            ),
        );
    }
}

fn not_applicable(name: &'static str, kind: BinaryKind, why: &'static str) -> Mitigation {
    Mitigation::new(
        name,
        Verdict::NotApplicable,
        format!("not applicable to a {}", kind.name()),
        Vec::new(),
        why,
    )
}

fn cfi_verdict(info: &ElfInfo, kind: BinaryKind) -> Mitigation {
    if kind == BinaryKind::Core {
        return not_applicable("CFI", kind, mit::WHY_CFI);
    }
    let (pr_type, features, how): (u32, [(u32, &str); 2], &str) = match info.header.e_machine.value
    {
        EM_X86_64 | EM_386 => (
            GNU_PROPERTY_X86_FEATURE_1_AND,
            [
                (
                    GNU_PROPERTY_X86_FEATURE_1_IBT,
                    "IBT (indirect branch tracking)",
                ),
                (GNU_PROPERTY_X86_FEATURE_1_SHSTK, "SHSTK (shadow stack)"),
            ],
            "-fcf-protection",
        ),
        EM_AARCH64 => (
            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
            [
                (
                    GNU_PROPERTY_AARCH64_FEATURE_1_BTI,
                    "BTI (branch target identification)",
                ),
                (
                    GNU_PROPERTY_AARCH64_FEATURE_1_PAC,
                    "PAC (return-address signing)",
                ),
            ],
            "-mbranch-protection=standard",
        ),
        EM_RISCV => (
            GNU_PROPERTY_RISCV_FEATURE_1_AND,
            [
                (
                    GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED,
                    "Zicfilp (landing pads)",
                ),
                (
                    GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS,
                    "Zicfiss (shadow stack)",
                ),
            ],
            "the Zicfilp/Zicfiss extensions",
        ),
        _ => {
            return Mitigation::new(
                "CFI",
                Verdict::NotApplicable,
                "no hardware CFI marking is defined for this architecture",
                Vec::new(),
                mit::WHY_CFI,
            );
        }
    };
    let and_rule = Evidence::new(
        "the linker keeps a feature only if every linked object has it, so one object built without it clears the mark",
    );
    let Some(note) = info.property_note() else {
        return Mitigation::new(
            "CFI",
            Verdict::Disabled,
            "not marked: no GNU property note",
            vec![
                Evidence::new(format!(
                    "no NT_GNU_PROPERTY_TYPE_0 note: built without {how}, or by a toolchain that does not record it"
                )),
                and_rule,
            ],
            mit::WHY_CFI,
        );
    };
    let Some(prop) = note
        .properties()
        .iter()
        .find(|p| p.pr_type.value == pr_type)
    else {
        return Mitigation::new(
            "CFI",
            Verdict::Disabled,
            "not marked: the property note has no CFI feature entry",
            vec![
                Evidence::at(
                    format!("GNU property note without property {pr_type:#x}"),
                    note.span,
                ),
                and_rule,
            ],
            mit::WHY_CFI,
        );
    };
    let Some(bits) = &prop.bits else {
        return Mitigation::new(
            "CFI",
            Verdict::Unknown,
            "the CFI feature property is corrupt",
            vec![Evidence::at(prop.text.clone(), prop.pr_type.span)],
            mit::WHY_CFI,
        );
    };
    let (have, missing): (Vec<_>, Vec<_>) = features.iter().partition(|(b, _)| bits.value & b != 0);
    let names = |v: &[&(u32, &str)]| {
        v.iter()
            .map(|(_, n)| n.split(' ').next().unwrap_or(n))
            .collect::<Vec<_>>()
            .join(" and ")
    };
    let (verdict, summary) = match (have.len(), missing.len()) {
        (_, 0) => (Verdict::Enabled, format!("marked for {}", names(&have))),
        (0, _) => (
            Verdict::Disabled,
            "not marked: no CFI feature bits set".to_string(),
        ),
        _ => (
            Verdict::Partial,
            format!("marked for {} only, not {}", names(&have), names(&missing)),
        ),
    };
    let mut evidence = vec![Evidence::at(prop.text.clone(), bits.span)];
    for (_, n) in &have {
        evidence.push(Evidence::new(format!("{n}: compiled in")));
    }
    for (_, n) in &missing {
        evidence.push(Evidence::new(format!("{n}: missing")));
    }
    evidence.push(and_rule);
    evidence.push(Evidence::new(
        "a mark means the code is compatible; enforcement also needs CPU, kernel and C library support",
    ));
    Mitigation::new("CFI", verdict, summary, evidence, mit::WHY_CFI)
}

/// Bytes of the file mapped executable, rounded out to 4 KiB pages as the kernel maps them.
fn executable_file_ranges(info: &ElfInfo) -> Vec<(&ProgramHeader, u64, u64)> {
    const PAGE: u64 = 0x1000;
    info.headers_of(PT_LOAD)
        .filter(|p| p.perms().execute && p.p_filesz.value > 0)
        .map(|p| {
            let start = p.p_offset.value & !(PAGE - 1);
            let end = p
                .p_offset
                .value
                .saturating_add(p.p_filesz.value)
                .saturating_add(PAGE - 1)
                & !(PAGE - 1);
            (p, start, end)
        })
        .collect()
}

fn separate_code_verdict(info: &ElfInfo, kind: BinaryKind) -> Mitigation {
    const NAME: &str = "SepCode";
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return not_applicable(NAME, kind, mit::WHY_SEPARATE_CODE);
    }
    if info.headers_of(PT_LOAD).next().is_none() {
        return Mitigation::new(
            NAME,
            Verdict::NotApplicable,
            "no LOAD segments",
            Vec::new(),
            mit::WHY_SEPARATE_CODE,
        );
    }
    let wx: Vec<Evidence> = info
        .headers_of(PT_LOAD)
        .filter(|p| p.perms().is_wx())
        .map(|p| {
            Evidence::at(
                format!("LOAD #{} is writable and executable", p.index),
                p.p_flags.span,
            )
        })
        .collect();
    if !wx.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::Disabled,
            "a segment is both writable and executable",
            wx,
            mit::WHY_SEPARATE_CODE,
        );
    }
    let mut exposed = Vec::new();
    let mut clean = Vec::new();
    for (p, start, end) in executable_file_ranges(info) {
        let mut non_code: Vec<&str> = Vec::new();
        let mut code: Vec<&str> = Vec::new();
        for s in info.section_headers.iter().filter(|s| s.is_alloc()) {
            let r = s.file_range();
            if r.len == 0 || r.offset.0 >= end || r.offset.0.saturating_add(r.len) <= start {
                continue;
            }
            if s.sh_flags.value & SHF_EXECINSTR != 0 {
                code.push(s.name_str());
            } else {
                non_code.push(s.name_str());
            }
        }
        if start == 0 {
            exposed.push(Evidence::at(
                format!(
                    "LOAD #{} is executable and maps the ELF header and program headers (file offset 0)",
                    p.index
                ),
                p.p_offset.span,
            ));
        }
        if !non_code.is_empty() {
            exposed.push(Evidence::at(
                format!(
                    "LOAD #{} also maps {} non-code section(s) as executable: {}",
                    p.index,
                    non_code.len(),
                    non_code.join(" ")
                ),
                p.span,
            ));
        } else if start != 0 {
            clean.push(Evidence::at(
                if code.is_empty() {
                    format!(
                        "LOAD #{} does not map the file headers (no section headers to check further)",
                        p.index
                    )
                } else {
                    format!("LOAD #{} maps only code: {}", p.index, code.join(" "))
                },
                p.span,
            ));
        }
    }
    if exposed.is_empty() {
        Mitigation::new(
            NAME,
            Verdict::Enabled,
            "code has its own segment",
            clean,
            mit::WHY_SEPARATE_CODE,
        )
    } else {
        exposed.push(Evidence::new(
            "the kernel maps whole 4 KiB pages, so everything sharing a page with code is executable too",
        ));
        Mitigation::new(
            NAME,
            Verdict::Partial,
            "no writable code, but headers or read-only data are executable (linked with -z noseparate-code?)",
            exposed,
            mit::WHY_SEPARATE_CODE,
        )
    }
}

fn library_paths_verdict(info: &ElfInfo, kind: BinaryKind) -> Mitigation {
    const NAME: &str = "LibPath";
    if matches!(kind, BinaryKind::Relocatable | BinaryKind::Core) {
        return not_applicable(NAME, kind, mit::WHY_LIBRARY_PATHS);
    }
    if info.dynamic.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::NotApplicable,
            "not dynamically linked: no libraries are searched for",
            Vec::new(),
            mit::WHY_LIBRARY_PATHS,
        );
    }
    let s = &info.strings;
    let paths: Vec<(&str, &Field<String>)> = [("RPATH", &s.rpath), ("RUNPATH", &s.runpath)]
        .into_iter()
        .filter_map(|(n, f)| f.as_ref().map(|f| (n, f)))
        .collect();
    if paths.is_empty() {
        return Mitigation::new(
            NAME,
            Verdict::Enabled,
            "no RPATH or RUNPATH: libraries come from the system search path",
            Vec::new(),
            mit::WHY_LIBRARY_PATHS,
        );
    }
    let mut worst = Verdict::Enabled;
    let rank = |v: Verdict| match v {
        Verdict::Disabled => 2,
        Verdict::Partial => 1,
        _ => 0,
    };
    let mut evidence = Vec::new();
    for (tag, f) in &paths {
        for entry in f.value.split(':') {
            let (v, what) = if entry.is_empty() {
                (
                    Verdict::Disabled,
                    "empty entry: the current directory of whoever runs the program".to_string(),
                )
            } else if entry.contains("$ORIGIN") || entry.contains("${ORIGIN}") {
                (
                    Verdict::Partial,
                    "relative to the binary's own directory: safe only if that directory is not writable by others \
                     (the dynamic linker ignores it for setuid programs)"
                        .to_string(),
                )
            } else if !entry.starts_with('/') {
                (
                    Verdict::Disabled,
                    "relative path: resolved from the current directory of whoever runs the program".to_string(),
                )
            } else {
                (
                    Verdict::Enabled,
                    "absolute path (whether others can write to it depends on the target system)"
                        .to_string(),
                )
            };
            if rank(v) > rank(worst) {
                worst = v;
            }
            evidence.push(Evidence::at(
                format!("{tag} entry {entry:?}: {what}"),
                f.span,
            ));
        }
    }
    if s.rpath.is_some() && s.runpath.is_some() {
        evidence.push(Evidence::new(
            "both are set: glibc ignores RPATH when RUNPATH is present",
        ));
    } else if s.rpath.is_some() {
        evidence.push(Evidence::new(
            "RPATH is searched before LD_LIBRARY_PATH and also applies to the libraries' own dependencies",
        ));
    }
    let list = paths
        .iter()
        .map(|(t, f)| format!("{t} {}", f.value))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = match worst {
        Verdict::Disabled => {
            format!("{list}: libraries can be loaded from attacker-chosen directories")
        }
        Verdict::Partial => format!("{list}: libraries load relative to the binary's location"),
        _ => format!("{list}: absolute search paths"),
    };
    Mitigation::new(NAME, worst, summary, evidence, mit::WHY_LIBRARY_PATHS)
}
