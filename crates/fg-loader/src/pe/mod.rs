//! PE loader (Windows executables and DLLs, UEFI images).
//!
//! Supports PE32 and PE32+ for every machine type, so later architectures need
//! no loader changes. Loading follows what the Windows loader looks at: the DOS
//! header's `e_lfanew`, the NT headers, the section table (mapped with the
//! loader's rounding rules), then the data directories, each read through the
//! image map rather than through section names.

mod coff;
pub mod consts;
mod debug;
mod exception;
mod exports;
mod header;
mod imports;
mod loadcfg;
mod mitigations;
mod reloc;
mod resource;
mod section;

pub use coff::CoffSymbol;
pub use debug::{DebugContent, DebugEntry};
pub use exception::{Arm64Packed, Arm64Xdata, RuntimeFunction, UnwindCode, UnwindInfo, X64Unwind};
pub use exports::{ExportDirectory, ExportEntry};
pub use header::{DataDirectory, DosHeader, FileHeader, OptionalHeader, RichEntry, RichHeader};
pub use imports::{BoundImport, DelayFields, ImportEntry, ImportKind, ImportedDll};
pub use loadcfg::{GuardEntry, LoadConfig, LoadConfigField, TlsDirectory};
pub use reloc::BaseRelocBlock;
pub use resource::{Resource, ResourceName};
pub use section::{MappedRegion, SectionHeader};

use crate::LoadError;
use crate::model::{
    BinaryKind, Format, FormatMetadata, LoadOptions, LoadedBinary, RelocKind, Relocation, Seed,
    SeedKind, Segment, Symbol, SymbolBinding, SymbolKind, SymbolRef, SymbolTable,
};
use consts::*;
use fg_core::{
    Anomaly, ArchId, Bitness, ByteView, Endian, Field, FileOffset, Perms, Severity, Span, Va,
};
use section::{Image, PAGE_SIZE, RAW_POINTER_GRANULARITY};
use serde::Serialize;

/// One entry of the certificate table (Authenticode signatures).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Certificate {
    /// Length of the entry, header included.
    pub length: Field<u32>,
    /// `WIN_CERTIFICATE` revision.
    pub revision: Field<u16>,
    /// `WIN_CERT_TYPE_*`.
    pub cert_type: Field<u16>,
    /// The certificate data (for Authenticode, a PKCS#7 SignedData blob).
    pub data: Span,
}

/// The .NET (CLR) runtime header. Managed code itself is out of scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ClrHeader {
    /// Runtime major version.
    pub major_runtime_version: Field<u16>,
    /// Runtime minor version.
    pub minor_runtime_version: Field<u16>,
    /// `COMIMAGE_FLAGS_*` (1 = IL only, 2 = 32-bit required...).
    pub flags: Field<u32>,
    /// The header's bytes.
    pub span: Span,
}

/// PE-specific details kept alongside the neutral model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct PeInfo {
    /// DOS header.
    pub dos: DosHeader,
    /// Rich header (Microsoft toolchain fingerprint), if present.
    pub rich: Option<RichHeader>,
    /// COFF file header.
    pub file_header: FileHeader,
    /// Optional header.
    pub optional: OptionalHeader,
    /// Section headers that could be read, in table order.
    pub sections: Vec<SectionHeader>,
    /// How the loader maps the file: headers first, then each section.
    pub regions: Vec<MappedRegion>,
    /// Imported DLLs (resolved at startup).
    pub imports: Vec<ImportedDll>,
    /// Delay-loaded DLLs (resolved on first call).
    pub delay_imports: Vec<ImportedDll>,
    /// Bound-import descriptors (pre-resolved addresses).
    pub bound_imports: Vec<BoundImport>,
    /// Export directory.
    pub exports: Option<ExportDirectory>,
    /// Base relocation blocks (the relocations themselves are in the neutral model).
    pub base_reloc_blocks: Vec<BaseRelocBlock>,
    /// TLS directory.
    pub tls: Option<TlsDirectory>,
    /// Load configuration.
    pub load_config: Option<LoadConfig>,
    /// Exception table.
    pub exception: Vec<RuntimeFunction>,
    /// Debug directory.
    pub debug: Vec<DebugEntry>,
    /// Resources (leaves of the resource tree).
    pub resources: Vec<Resource>,
    /// Certificate table (Authenticode signatures).
    pub certificates: Vec<Certificate>,
    /// .NET runtime header.
    pub clr: Option<ClrHeader>,
    /// COFF symbols (MinGW-style images only).
    pub coff_symbols: Vec<CoffSymbol>,
    /// Image checksum recomputed the way `MapFileAndCheckSum` does.
    pub computed_checksum: u32,
    /// Bytes after the last section's data that no header accounts for.
    pub overlay: Option<Span>,
}

impl PeInfo {
    /// True for PE32+ (64-bit) images.
    pub fn is_pe32_plus(&self) -> bool {
        self.optional.is_pe32_plus()
    }

    /// The section whose memory range covers `rva`.
    pub fn section_at(&self, rva: u64) -> Option<&SectionHeader> {
        self.regions
            .iter()
            .skip(1)
            .find(|r| rva >= r.rva && rva - r.rva < r.mem_size)
            .and_then(|r| r.section)
            .and_then(|i| self.sections.get(i as usize))
    }

    /// Extended DLL characteristics from the debug directory (CET marking), if any.
    pub fn ex_dll_characteristics(&self) -> Option<&Field<u32>> {
        self.debug.iter().find_map(|d| match &d.content {
            DebugContent::ExDllCharacteristics(f) => Some(f),
            _ => None,
        })
    }

    /// Data directory `index`, if declared and in use.
    pub fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.optional.directory(index)
    }
}

/// True if `bytes` starts with the DOS magic `MZ`.
pub fn is_pe(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
}

fn malformed(reason: &str, anomalies: Vec<Anomaly>) -> LoadError {
    LoadError::Malformed {
        reason: reason.to_string(),
        anomalies,
    }
}

/// Loads a PE image.
pub fn load(bytes: &[u8], options: &LoadOptions) -> Result<LoadedBinary, LoadError> {
    let limits = options.limits;
    let mut anomalies = Vec::new();
    let view = ByteView::new(bytes, Endian::Little);
    if !is_pe(bytes) {
        return Err(LoadError::NotRecognized {
            magic: bytes.iter().take(4).copied().collect(),
        });
    }
    let dos = match DosHeader::parse(&view) {
        Ok(d) => d,
        Err(_) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "pe.dos.truncated",
                    format!("file is {} bytes but the DOS header needs 64", view.len()),
                )
                .at(Span::new(0, view.len())),
            );
            return Err(malformed("file ends inside the DOS header", anomalies));
        }
    };
    let nt = u64::from(dos.e_lfanew.value);
    let signature = view.u32(nt).ok();
    if nt < 4 || signature != Some(IMAGE_NT_SIGNATURE) {
        let what = match view.u16(nt).ok() {
            _ if nt == 0 || !view.contains(nt, 4) => "DOS program (e_lfanew points nowhere)",
            Some(0x454e) => "16-bit NE executable (Windows 3.x / OS/2)",
            Some(0x454c) | Some(0x584c) => "LE/LX executable (VxD / OS/2)",
            _ => "DOS program (no PE signature at e_lfanew)",
        };
        anomalies.push(
            Anomaly::new(
                Severity::Error,
                "pe.nt.signature",
                format!("no PE\\0\\0 signature at e_lfanew {nt:#x}: {what}"),
            )
            .at(dos.e_lfanew.span),
        );
        return Err(malformed(&format!("not a PE image: {what}"), anomalies));
    }
    if !nt.is_multiple_of(4) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.dos.lfanew_unaligned",
                format!("e_lfanew {nt:#x} is not a multiple of 4"),
            )
            .at(dos.e_lfanew.span)
            .os("Windows requires the NT headers to be 4-byte aligned and refuses the file"),
        );
    }
    let file_header = match FileHeader::parse(&view, nt + 4) {
        Ok(h) => h,
        Err(_) => {
            anomalies.push(Anomaly::new(
                Severity::Error,
                "pe.file.truncated",
                "file ends inside the COFF file header",
            ));
            return Err(malformed(
                "file ends inside the COFF file header",
                anomalies,
            ));
        }
    };
    let opt_at = nt + 4 + FILE_HEADER_SIZE;
    let magic = view.u16(opt_at).unwrap_or(0);
    if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let what = if magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC {
            "ROM image".to_string()
        } else if file_header.size_of_optional_header.value == 0 {
            "no optional header (an object file, not an image)".to_string()
        } else {
            format!("unknown optional header magic {magic:#x}")
        };
        anomalies.push(
            Anomaly::new(Severity::Error, "pe.optional.magic", what.clone())
                .at(Span::new(opt_at, 2))
                .os("Windows refuses to load the file"),
        );
        return Err(malformed(&format!("unsupported PE: {what}"), anomalies));
    }
    let optional = match OptionalHeader::parse(&view, opt_at) {
        Ok(o) => o,
        Err(_) => {
            anomalies.push(
                Anomaly::new(
                    Severity::Error,
                    "pe.optional.truncated",
                    "file ends inside the optional header",
                )
                .at(Span::new(opt_at, view.len().saturating_sub(opt_at))),
            );
            return Err(malformed("file ends inside the optional header", anomalies));
        }
    };
    let pe32_plus = optional.is_pe32_plus();
    let machine = file_header.machine.value;
    let rich = header::parse_rich(&view, nt);

    // Section table: SizeOfOptionalHeader is really the distance to it.
    let sec_at = opt_at + u64::from(file_header.size_of_optional_header.value);
    let strtab = (file_header.pointer_to_symbol_table.value != 0)
        .then(|| {
            coff::string_table_size(
                &view,
                u64::from(file_header.pointer_to_symbol_table.value),
                u64::from(file_header.number_of_symbols.value),
            )
        })
        .flatten();
    let sections = read_sections(&view, &file_header, sec_at, strtab, &limits, &mut anomalies);

    let image = Image::new(
        view,
        optional.image_base.value,
        u64::from(optional.size_of_headers.value),
        u64::from(optional.section_alignment.value),
        &sections,
    );
    check_headers(
        &view,
        &file_header,
        &optional,
        &sections,
        sec_at,
        &mut anomalies,
    );
    check_sections(&view, &optional, &sections, &mut anomalies);
    check_directories(&image, &optional, &mut anomalies);

    let dir = |i: usize| {
        optional
            .directory(i)
            .map(|d| (u64::from(d.rva.value), u64::from(d.size.value)))
    };
    let ictx = imports::Ctx {
        image: &image,
        pe32_plus,
        max_libraries: limits.max_libraries,
        max_entries: limits.max_table_entries,
        max_name_len: limits.max_name_len,
        budget: std::cell::Cell::new(Some(limits.max_imports)),
    };
    let imports = dir(DIR_IMPORT)
        .map(|(r, s)| imports::read_imports(&ictx, r, s, &mut anomalies))
        .unwrap_or_default();
    let delay_imports = dir(DIR_DELAY_IMPORT)
        .map(|(r, _)| imports::read_delay_imports(&ictx, r, &mut anomalies))
        .unwrap_or_default();
    let bound_imports = dir(DIR_BOUND_IMPORT)
        .map(|(r, _)| imports::read_bound(&ictx, r, &mut anomalies))
        .unwrap_or_default();
    let exports = dir(DIR_EXPORT).and_then(|(r, s)| {
        exports::read(
            &image,
            r,
            s,
            limits.max_table_entries,
            limits.max_name_len,
            &mut anomalies,
        )
    });
    let (base_reloc_blocks, base_relocs) = dir(DIR_BASERELOC)
        .map(|(r, s)| {
            reloc::read(
                &image,
                machine,
                r,
                s,
                limits.max_relocations,
                &mut anomalies,
            )
        })
        .unwrap_or_default();
    let tls = dir(DIR_TLS).and_then(|(r, _)| {
        loadcfg::read_tls(
            &image,
            pe32_plus,
            r,
            limits.max_table_entries,
            &mut anomalies,
        )
    });
    let load_config = dir(DIR_LOAD_CONFIG).and_then(|(r, s)| {
        loadcfg::read_load_config(
            &image,
            pe32_plus,
            r,
            s,
            limits.max_table_entries,
            &mut anomalies,
        )
    });
    let exception = dir(DIR_EXCEPTION)
        .map(|(r, s)| {
            exception::read(
                &image,
                machine,
                r,
                s,
                limits.max_table_entries,
                &mut anomalies,
            )
        })
        .unwrap_or_default();
    let debug = dir(DIR_DEBUG)
        .map(|(r, s)| {
            debug::read(
                &image,
                r,
                s,
                limits.max_table_entries,
                limits.max_name_len,
                &mut anomalies,
            )
        })
        .unwrap_or_default();
    let resources = match dir(DIR_RESOURCE) {
        Some((r, _)) => {
            let mut w = resource::Walker {
                image: &image,
                root: r,
                max_depth: limits.max_resource_depth,
                max_resources: limits.max_resources,
                out: Vec::new(),
                visited: Default::default(),
                limit_hit: false,
                loop_hit: false,
            };
            w.walk(0, &mut Vec::new(), &mut anomalies);
            w.out
        }
        None => Vec::new(),
    };
    let certificates = optional
        .directory(DIR_SECURITY)
        .map(|d| read_certificates(&view, d, &sections, &mut anomalies))
        .unwrap_or_default();
    let clr = dir(DIR_CLR).and_then(|(r, _)| read_clr(&image, r, &mut anomalies));
    let coff_symbols = match file_header.pointer_to_symbol_table.value {
        0 => Vec::new(),
        p if u64::from(p) >= view.len() => {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "pe.coff.pointer_invalid",
                    format!("COFF symbol table pointer {p:#x} is beyond the end of the file"),
                )
                .at(file_header.pointer_to_symbol_table.span),
            );
            Vec::new()
        }
        p => coff::read_symbols(
            &view,
            u64::from(p),
            file_header.number_of_symbols.value,
            limits.max_symbols,
            limits.max_name_len,
            &mut anomalies,
        ),
    };
    let computed_checksum = checksum(bytes, optional.checksum.span.offset.0);
    let overlay = overlay(&view, &sections, &optional, &file_header, strtab);
    if let Some(o) = overlay {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.overlay",
                format!(
                    "{} bytes after the last section (overlay): not mapped, but installers and droppers keep payloads there",
                    o.len
                ),
            )
            .at(o),
        );
    }
    if let Some(r) = &rich
        && !r.checksum_valid()
    {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.rich.checksum",
                format!(
                    "Rich header key {:#010x} does not match its checksum {:#010x}: the toolchain fingerprint was edited or copied from another file",
                    r.key.value, r.computed_checksum
                ),
            )
            .at(r.key.span),
        );
    }
    let stored_sum = optional.checksum.value;
    let is_driver = optional.subsystem.value == 1;
    if (stored_sum != 0 || is_driver) && stored_sum != computed_checksum {
        anomalies.push(
            Anomaly::new(
                if is_driver { Severity::Warning } else { Severity::Info },
                "pe.optional.checksum",
                format!("image checksum {stored_sum:#x} does not match the computed {computed_checksum:#x}"),
            )
            .at(optional.checksum.span)
            .os("Windows checks it only for drivers and DLLs loaded into critical system processes"),
        );
    }

    let info = PeInfo {
        dos,
        rich,
        file_header,
        optional,
        regions: image.regions.clone(),
        sections,
        imports,
        delay_imports,
        bound_imports,
        exports,
        base_reloc_blocks,
        tls,
        load_config,
        exception,
        debug,
        resources,
        certificates,
        clr,
        coff_symbols,
        computed_checksum,
        overlay,
    };
    if info.clr.is_some() {
        anomalies.push(Anomaly::new(
            Severity::Info,
            "pe.clr",
            ".NET assembly: its methods are CIL bytecode, which is out of scope; only the native stub is modelled",
        ));
    }

    let arch = arch_of(machine);
    if arch == ArchId::Unknown {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.machine.unknown",
                format!(
                    "machine {:#x} ({}) is not supported for analysis",
                    machine,
                    machine_name(machine).unwrap_or("unknown")
                ),
            )
            .at(info.file_header.machine.span),
        );
    }
    let bitness = if pe32_plus {
        Bitness::Bits64
    } else {
        Bitness::Bits32
    };
    let kind = classify(&info);
    let entry = entry_point(&info);
    check_entry(&info, entry.as_ref(), &mut anomalies);
    let segments = neutral_segments(&info);
    let symbols = neutral_symbols(&info);
    let relocations = neutral_relocations(&info, &symbols, &base_relocs);
    let seeds = neutral_seeds(&info, entry.as_ref());
    let libraries = info.imports.iter().map(|d| d.name.clone()).collect();
    let build_id = info.debug.iter().find_map(|d| match &d.content {
        DebugContent::CodeView {
            guid,
            symbol_server_key,
            ..
        } => Some(Field::new(
            symbol_server_key.clone(),
            Span::new(guid.span.offset.0, 20),
        )),
        _ => None,
    });
    let mitigations = mitigations::report(&info, kind, &symbols, base_relocs.len());

    anomalies.sort_by_key(|a| std::cmp::Reverse(a.severity));
    Ok(LoadedBinary {
        format: Format::Pe,
        arch,
        bitness,
        endian: Endian::Little,
        kind,
        entry,
        file_size: view.len(),
        segments,
        sections: neutral_sections(&info),
        symbols,
        relocations,
        libraries,
        build_id,
        seeds,
        mitigations,
        anomalies,
        metadata: FormatMetadata::Pe(Box::new(info)),
    })
}

fn arch_of(machine: u16) -> ArchId {
    match machine {
        IMAGE_FILE_MACHINE_I386 => ArchId::X86,
        IMAGE_FILE_MACHINE_AMD64 => ArchId::X86_64,
        IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X => {
            ArchId::Aarch64
        }
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT | IMAGE_FILE_MACHINE_THUMB => ArchId::Arm,
        IMAGE_FILE_MACHINE_RISCV32 | IMAGE_FILE_MACHINE_RISCV64 | IMAGE_FILE_MACHINE_RISCV128 => {
            ArchId::RiscV
        }
        _ => ArchId::Unknown,
    }
}

fn read_sections(
    view: &ByteView<'_>,
    fh: &FileHeader,
    at: u64,
    strtab: Option<(u64, u32)>,
    limits: &crate::model::Limits,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<SectionHeader> {
    let n = u32::from(fh.number_of_sections.value);
    if n == 0 {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.section.none",
                "image has no sections",
            )
            .at(fh.number_of_sections.span),
        );
    }
    if n > limits.max_sections {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.section.limit",
                format!(
                    "{n} sections declared; only {} are read",
                    limits.max_sections
                ),
            )
            .at(fh.number_of_sections.span),
        );
    }
    let mut out = Vec::new();
    for i in 0..n.min(limits.max_sections) {
        let off = at + u64::from(i) * SECTION_HEADER_SIZE;
        match SectionHeader::parse(view, off, i) {
            Ok(mut s) => {
                // "/123": the real name is at offset 123 of the COFF string table.
                if let Some(digits) = s.name.strip_prefix('/')
                    && let Ok(o) = digits.parse::<u64>()
                {
                    match strtab.and_then(|(t, size)| {
                        coff::string_at(view, t, size, o, limits.max_name_len)
                    }) {
                        Some(long) => s.name = long,
                        None => anomalies.push(
                            Anomaly::new(
                                Severity::Info,
                                "pe.section.name_invalid",
                                format!("section #{i} long name {:?} cannot be resolved", s.name),
                            )
                            .at(s.raw_name.span),
                        ),
                    }
                }
                out.push(s);
            }
            Err(_) => {
                anomalies.push(
                    Anomaly::new(
                        Severity::Error,
                        "pe.section.table_truncated",
                        format!("section table ends at header {i} of {n}: the file is too short"),
                    )
                    .at(Span::new(off, view.len().saturating_sub(off))),
                );
                break;
            }
        }
    }
    out
}

fn check_headers(
    view: &ByteView<'_>,
    fh: &FileHeader,
    o: &OptionalHeader,
    sections: &[SectionHeader],
    sec_at: u64,
    anomalies: &mut Vec<Anomaly>,
) {
    let plus = o.is_pe32_plus();
    let m = fh.machine.value;
    let wants_64 = matches!(
        m,
        IMAGE_FILE_MACHINE_AMD64
            | IMAGE_FILE_MACHINE_ARM64
            | IMAGE_FILE_MACHINE_ARM64EC
            | IMAGE_FILE_MACHINE_ARM64X
            | IMAGE_FILE_MACHINE_IA64
            | IMAGE_FILE_MACHINE_RISCV64
            | IMAGE_FILE_MACHINE_LOONGARCH64
    );
    let wants_32 = matches!(
        m,
        IMAGE_FILE_MACHINE_I386
            | IMAGE_FILE_MACHINE_ARMNT
            | IMAGE_FILE_MACHINE_ARM
            | IMAGE_FILE_MACHINE_THUMB
            | IMAGE_FILE_MACHINE_RISCV32
            | IMAGE_FILE_MACHINE_LOONGARCH32
    );
    if (plus && wants_32) || (!plus && wants_64) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.magic_machine",
                format!(
                    "{} optional header for a {} machine",
                    if plus { "PE32+" } else { "PE32" },
                    machine_name(m).unwrap_or("?")
                ),
            )
            .at(o.magic.span),
        );
    }
    if !fh.has(IMAGE_FILE_EXECUTABLE_IMAGE) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.file.not_executable",
                "IMAGE_FILE_EXECUTABLE_IMAGE is not set: the linker marked this image as unusable",
            )
            .at(fh.characteristics.span),
        );
    }
    let ndirs = u64::from(
        o.number_of_rva_and_sizes
            .value
            .min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    );
    let declared = u64::from(fh.size_of_optional_header.value);
    if declared < OptionalHeader::fixed_size(plus) + ndirs * 8 {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.optional.size_small",
                format!(
                    "SizeOfOptionalHeader {declared:#x} is smaller than the optional header: the section table overlaps it"
                ),
            )
            .at(fh.size_of_optional_header.span)
            .os("Windows places the section table at the optional header plus SizeOfOptionalHeader, whatever the header's real size"),
        );
    }
    let nrva = o.number_of_rva_and_sizes.value;
    if nrva != IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.optional.rva_count",
                format!("NumberOfRvaAndSizes is {nrva}, not 16"),
            )
            .at(o.number_of_rva_and_sizes.span)
            .os(if nrva > IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
                "Windows uses only the first 16 directories"
            } else {
                "directories beyond the declared count are treated as absent"
            }),
        );
    }
    let sa = u64::from(o.section_alignment.value);
    let fa = u64::from(o.file_alignment.value);
    if sa < PAGE_SIZE {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.optional.low_alignment",
                format!(
                    "section alignment {sa:#x} is below the page size: sections share pages, so their permissions cannot all be applied"
                ),
            )
            .at(o.section_alignment.span),
        );
        if fa != sa {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.optional.alignment",
                    format!("low-alignment image with file alignment {fa:#x} != section alignment {sa:#x}"),
                )
                .at(o.file_alignment.span)
                .os("Windows requires the two to be equal in low-alignment images"),
            );
        }
    } else if !fa.is_power_of_two()
        || !sa.is_power_of_two()
        || fa > sa
        || !(0x200..=0x10000).contains(&fa)
    {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.alignment",
                format!(
                    "unusual alignment: file {fa:#x}, section {sa:#x} (expected powers of two, 0x200 <= file <= 0x10000, file <= section)"
                ),
            )
            .at(o.file_alignment.span),
        );
    }
    let base = o.image_base.value;
    if !base.is_multiple_of(0x1_0000) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.image_base",
                format!("image base {base:#x} is not a multiple of 64 KiB"),
            )
            .at(o.image_base.span),
        );
    }
    let soi = u64::from(o.size_of_image.value);
    if base.checked_add(soi).is_none() || (!plus && base + soi > 0x1_0000_0000) {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.image_base",
                format!("image base {base:#x} + size {soi:#x} overflows the address space"),
            )
            .at(o.image_base.span),
        );
    }
    let max_end = sections
        .iter()
        .map(|s| u64::from(s.virtual_address.value) + s.mem_size())
        .max()
        .unwrap_or(0);
    if max_end > soi {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.size_of_image",
                format!("SizeOfImage {soi:#x} is smaller than the end of the last section ({max_end:#x})"),
            )
            .at(o.size_of_image.span),
        );
    }
    let soh = u64::from(o.size_of_headers.value);
    let table_end = sec_at + sections.len() as u64 * SECTION_HEADER_SIZE;
    if soh < table_end {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.optional.size_of_headers",
                format!("SizeOfHeaders {soh:#x} does not cover the section table (ends at {table_end:#x})"),
            )
            .at(o.size_of_headers.span),
        );
    }
    if soh > view.len() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.size_of_headers",
                format!(
                    "SizeOfHeaders {soh:#x} is larger than the file ({:#x} bytes)",
                    view.len()
                ),
            )
            .at(o.size_of_headers.span),
        );
    }
    if let Some(first) = sections
        .iter()
        .map(|s| u64::from(s.virtual_address.value))
        .min()
        && soh > first
    {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.optional.size_of_headers",
                format!("headers ({soh:#x} bytes) overlap the first section at RVA {first:#x}"),
            )
            .at(o.size_of_headers.span),
        );
    }
    if o.win32_version_value.value != 0 || o.loader_flags.value != 0 {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.optional.reserved",
                format!(
                    "reserved fields are not zero (Win32VersionValue {:#x}, LoaderFlags {:#x})",
                    o.win32_version_value.value, o.loader_flags.value
                ),
            )
            .at(o.win32_version_value.span),
        );
    }
    if fh.has(IMAGE_FILE_RELOCS_STRIPPED) && o.directory(DIR_BASERELOC).is_some() {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.reloc.stripped_flag",
                "IMAGE_FILE_RELOCS_STRIPPED is set but the image has base relocations",
            )
            .at(fh.characteristics.span),
        );
    }
}

fn check_sections(
    view: &ByteView<'_>,
    o: &OptionalHeader,
    sections: &[SectionHeader],
    anomalies: &mut Vec<Anomaly>,
) {
    let low = u64::from(o.section_alignment.value) < PAGE_SIZE;
    let soi = u64::from(o.size_of_image.value);
    let mut prev: Option<&SectionHeader> = None;
    for s in sections {
        let va = u64::from(s.virtual_address.value);
        let ptr = u64::from(s.pointer_to_raw_data.value);
        let raw = u64::from(s.size_of_raw_data.value);
        let label = format!("section #{} {:?}", s.index, s.name);
        if ptr != 0 && raw != 0 && ptr.saturating_add(raw) > view.len() {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.section.raw_outside",
                    format!(
                        "{label} claims file bytes {ptr:#x}..{:#x} but the file ends at {:#x}",
                        ptr.saturating_add(raw),
                        view.len()
                    ),
                )
                .at(s.span),
            );
        }
        if !low && !ptr.is_multiple_of(RAW_POINTER_GRANULARITY) {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.section.raw_unaligned",
                    format!("{label} data at file offset {ptr:#x} is not a multiple of 0x200"),
                )
                .at(s.pointer_to_raw_data.span)
                .os("the Windows loader rounds the offset down to a multiple of 0x200, so the section's bytes start earlier than the header says"),
            );
        }
        if low && ptr != va && raw != 0 {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.section.low_alignment_mismatch",
                    format!("low-alignment image: {label} has RVA {va:#x} but file offset {ptr:#x}"),
                )
                .at(s.span)
                .os("in low-alignment images Windows maps the file as is, so RVA and file offset must match"),
            );
        }
        if s.perms().is_wx() {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.section.wx",
                    format!("{label} is writable and executable"),
                )
                .at(s.characteristics.span),
            );
        }
        if va + s.mem_size() > soi {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.section.beyond_image",
                    format!(
                        "{label} ends at RVA {:#x}, past SizeOfImage {soi:#x}",
                        va + s.mem_size()
                    ),
                )
                .at(s.span),
            );
        }
        if let Some(p) = prev {
            let p_end = u64::from(p.virtual_address.value) + p.mem_size();
            if va < p_end {
                anomalies.push(
                    Anomaly::new(
                        Severity::Warning,
                        "pe.section.overlap",
                        format!(
                            "{label} at RVA {va:#x} overlaps or precedes section #{} {:?} (ends at {p_end:#x})",
                            p.index, p.name
                        ),
                    )
                    .at(s.virtual_address.span),
                );
            }
        }
        prev = Some(s);
    }
}

fn check_directories(image: &Image<'_>, o: &OptionalHeader, anomalies: &mut Vec<Anomaly>) {
    let soi = u64::from(o.size_of_image.value);
    for d in &o.data_directories {
        let i = usize::from(d.index);
        if !d.is_present() {
            continue;
        }
        let (rva, size) = (u64::from(d.rva.value), u64::from(d.size.value));
        if matches!(i, DIR_ARCHITECTURE | DIR_RESERVED) || (i == DIR_GLOBALPTR && size != 0) {
            anomalies.push(
                Anomaly::new(
                    Severity::Info,
                    "pe.dir.reserved_used",
                    format!(
                        "reserved data directory {} ({}) is not zero",
                        d.index,
                        d.name()
                    ),
                )
                .at(d.rva.span),
            );
            continue;
        }
        if i == DIR_SECURITY || i == DIR_GLOBALPTR {
            continue; // a file offset / a register value, not a table in memory
        }
        if !image.is_mapped(rva) || rva.saturating_add(size) > soi {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.dir.outside",
                    format!(
                        "{} directory at RVA {rva:#x} (+{size:#x}) is outside the image",
                        d.name()
                    ),
                )
                .at(d.rva.span),
            );
        }
    }
}

fn read_certificates(
    view: &ByteView<'_>,
    d: &DataDirectory,
    sections: &[SectionHeader],
    anomalies: &mut Vec<Anomaly>,
) -> Vec<Certificate> {
    // The security directory holds a file offset, not an RVA: signatures are never mapped.
    let start = u64::from(d.rva.value);
    let size = u64::from(d.size.value);
    let end = start.saturating_add(size);
    if end > view.len() {
        anomalies.push(
            Anomaly::new(
                Severity::Warning,
                "pe.cert.outside",
                format!("certificate table at file offset {start:#x} (+{size:#x}) runs past the end of the file"),
            )
            .at(d.rva.span),
        );
    }
    if sections.iter().any(|s| {
        let p = u64::from(s.pointer_to_raw_data.value);
        p != 0 && start >= p && start < p + u64::from(s.size_of_raw_data.value)
    }) {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.cert.in_section",
                "certificate table lies inside a section's data",
            )
            .at(d.rva.span),
        );
    }
    let mut out = Vec::new();
    let mut at = start;
    while at + 8 <= end.min(view.len()) && out.len() < 64 {
        let (Ok(length), Ok(revision), Ok(cert_type)) = (
            view.field_u32(at),
            view.field_u16(at + 4),
            view.field_u16(at + 6),
        ) else {
            break;
        };
        let len = u64::from(length.value);
        if len < 8 || at + len > end {
            anomalies.push(
                Anomaly::new(
                    Severity::Warning,
                    "pe.cert.length",
                    format!("certificate entry at {at:#x} has invalid length {len:#x}"),
                )
                .at(length.span),
            );
            break;
        }
        out.push(Certificate {
            length,
            revision,
            cert_type,
            data: Span::new(at + 8, len - 8),
        });
        at += len.next_multiple_of(8);
    }
    if end < view.len() && start != 0 {
        anomalies.push(
            Anomaly::new(
                Severity::Info,
                "pe.cert.not_last",
                format!("{} bytes follow the certificate table", view.len() - end),
            )
            .at(Span::new(end, view.len() - end)),
        );
    }
    out
}

fn read_clr(image: &Image<'_>, rva: u64, anomalies: &mut Vec<Anomaly>) -> Option<ClrHeader> {
    let (Ok(cb), Ok(major), Ok(minor), Ok(flags)) = (
        image.u32(rva),
        image.u16(rva + 4),
        image.u16(rva + 6),
        image.u32(rva + 16),
    ) else {
        anomalies.push(Anomaly::new(
            Severity::Warning,
            "pe.clr.truncated",
            format!("CLR header at RVA {rva:#x} cannot be read"),
        ));
        return None;
    };
    Some(ClrHeader {
        major_runtime_version: major,
        minor_runtime_version: minor,
        flags,
        span: Span::new(cb.span.offset.0, u64::from(cb.value)),
    })
}

/// The PE checksum (`MapFileAndCheckSum`): a 16-bit ones'-complement-style sum
/// of the file with the checksum field skipped, plus the file length.
pub(crate) fn checksum(bytes: &[u8], field_offset: u64) -> u32 {
    let mut sum: u64 = 0;
    let skip = field_offset as usize..field_offset as usize + 4;
    for (i, pair) in bytes.chunks(2).enumerate() {
        let at = i * 2;
        if skip.contains(&at) {
            continue;
        }
        let w = u64::from(pair[0]) | pair.get(1).map_or(0, |&b| u64::from(b) << 8);
        sum += w;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(bytes.len() as u32)
}

/// Bytes after everything the headers account for (section data, COFF symbols
/// and string table, certificates).
fn overlay(
    view: &ByteView<'_>,
    sections: &[SectionHeader],
    o: &OptionalHeader,
    fh: &FileHeader,
    strtab: Option<(u64, u32)>,
) -> Option<Span> {
    let mut end = u64::from(o.size_of_headers.value);
    for s in sections {
        let p = u64::from(s.pointer_to_raw_data.value);
        if p != 0 {
            end = end.max(p.saturating_add(u64::from(s.size_of_raw_data.value)));
        }
    }
    if fh.pointer_to_symbol_table.value != 0 {
        let symend = u64::from(fh.pointer_to_symbol_table.value)
            + u64::from(fh.number_of_symbols.value) * COFF_SYMBOL_SIZE;
        end = end.max(symend);
        if let Some((t, n)) = strtab {
            end = end.max(t + u64::from(n));
        }
    }
    // The certificate table, when it is at the end, is not overlay.
    let cert = o.directory(DIR_SECURITY).map(|d| {
        (
            u64::from(d.rva.value),
            u64::from(d.rva.value) + u64::from(d.size.value),
        )
    });
    let len = view.len();
    let span = match cert {
        Some((cs, ce)) if cs >= end && ce >= len => (cs > end).then(|| Span::new(end, cs - end)),
        _ => (len > end).then(|| Span::new(end, len - end)),
    }?;
    // Zero padding up to the file alignment is not an overlay.
    let pad = u64::from(o.file_alignment.value).max(RAW_POINTER_GRANULARITY);
    let zeros = view
        .bytes(span.offset.0, span.len)
        .is_ok_and(|b| b.iter().all(|&x| x == 0));
    (!(zeros && span.len < pad)).then_some(span)
}

fn classify(info: &PeInfo) -> BinaryKind {
    let fh = &info.file_header;
    if fh.has(IMAGE_FILE_DLL) {
        BinaryKind::SharedObject
    } else if info.optional.has(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        && !fh.has(IMAGE_FILE_RELOCS_STRIPPED)
    {
        BinaryKind::PieExecutable
    } else {
        BinaryKind::Executable
    }
}

fn entry_point(info: &PeInfo) -> Option<Field<Va>> {
    let aep = &info.optional.address_of_entry_point;
    if aep.value == 0 && info.file_header.has(IMAGE_FILE_DLL) {
        return None;
    }
    Some(Field::new(
        Va(info
            .optional
            .image_base
            .value
            .wrapping_add(u64::from(aep.value))),
        aep.span,
    ))
}

fn check_entry(info: &PeInfo, entry: Option<&Field<Va>>, anomalies: &mut Vec<Anomaly>) {
    let Some(e) = entry else { return };
    let rva = u64::from(info.optional.address_of_entry_point.value);
    let section = info.section_at(rva);
    let (sev, code, msg) = if rva == 0 {
        (
            Severity::Warning,
            "pe.entry.zero",
            "entry point is 0: execution would start at the MZ header".to_string(),
        )
    } else if rva < u64::from(info.optional.size_of_headers.value) && section.is_none() {
        (
            Severity::Warning,
            "pe.entry.in_headers",
            format!("entry point {} is inside the headers", e.value),
        )
    } else {
        match section {
            None => (
                Severity::Error,
                "pe.entry.unmapped",
                format!("entry point {} is outside every section", e.value),
            ),
            Some(s) if !s.perms().execute => (
                Severity::Warning,
                "pe.entry.not_executable",
                format!(
                    "entry point {} is in non-executable section {:?}",
                    e.value, s.name
                ),
            ),
            Some(_) => return,
        }
    };
    anomalies.push(Anomaly::new(sev, code, msg).at(e.span));
}

fn neutral_segments(info: &PeInfo) -> Vec<Segment> {
    let base = info.optional.image_base.value;
    info.regions
        .iter()
        .map(|r| {
            let (name, perms, defined_by) =
                match r.section.and_then(|i| info.sections.get(i as usize)) {
                    Some(s) => (
                        if s.name.is_empty() {
                            format!("section #{}", s.index)
                        } else {
                            s.name.clone()
                        },
                        s.perms(),
                        s.span,
                    ),
                    None => (
                        "headers".to_string(),
                        Perms::new(true, false, false),
                        info.optional.size_of_headers.span,
                    ),
                };
            Segment::new(
                name,
                Va(base.wrapping_add(r.rva)),
                r.mem_size,
                FileOffset(r.file_offset),
                r.file_size,
                perms,
                defined_by,
            )
        })
        .collect()
}

fn neutral_sections(info: &PeInfo) -> Vec<crate::model::Section> {
    let base = info.optional.image_base.value;
    info.sections
        .iter()
        .map(|s| {
            crate::model::Section::new(
                s.name.clone(),
                Some(Va(base.wrapping_add(u64::from(s.virtual_address.value)))),
                FileOffset(u64::from(s.pointer_to_raw_data.value)),
                s.mem_size(),
                u64::from(s.size_of_raw_data.value),
                s.perms(),
                s.span,
            )
        })
        .collect()
}

fn neutral_symbols(info: &PeInfo) -> Vec<Symbol> {
    let base = info.optional.image_base.value;
    let mut out = Vec::new();
    for (table, dlls) in [
        (SymbolTable::Imports, &info.imports),
        (SymbolTable::DelayImports, &info.delay_imports),
    ] {
        let mut index = 0u32;
        for d in dlls {
            for e in &d.entries {
                out.push(
                    Symbol::new(
                        table,
                        index,
                        e.name
                            .as_ref()
                            .map_or_else(String::new, |n| n.value.clone()),
                        None,
                        e.iat_va,
                        0,
                        SymbolKind::NoType,
                        SymbolBinding::Global,
                        false,
                        e.thunk.span,
                    )
                    .with_library(Some(d.name.value.clone()))
                    .with_ordinal(e.ordinal.map(u32::from)),
                );
                index += 1;
            }
        }
    }
    if let Some(x) = &info.exports {
        let mut index = 0u32;
        for e in &x.entries {
            let rva = u64::from(e.rva.value);
            let kind = if e.forwarder.is_some() {
                SymbolKind::NoType
            } else if info.section_at(rva).is_some_and(|s| s.perms().execute) {
                SymbolKind::Function
            } else {
                SymbolKind::Object
            };
            let names: Vec<Option<&Field<String>>> = if e.names.is_empty() {
                vec![None]
            } else {
                e.names.iter().map(Some).collect()
            };
            for n in names {
                out.push(
                    Symbol::new(
                        SymbolTable::Exports,
                        index,
                        n.map_or_else(String::new, |n| n.value.clone()),
                        None,
                        Va(base.wrapping_add(rva)),
                        0,
                        kind,
                        SymbolBinding::Global,
                        true,
                        e.rva.span,
                    )
                    .with_ordinal(Some(e.ordinal))
                    .with_forwarder(e.forwarder.as_ref().map(|f| f.value.clone())),
                );
                index += 1;
            }
        }
    }
    for s in &info.coff_symbols {
        let sn = s.section_number.value;
        let class = s.storage_class.value;
        let va = match usize::try_from(sn)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| info.sections.get(i))
        {
            Some(sec) => base
                .wrapping_add(u64::from(sec.virtual_address.value))
                .wrapping_add(u64::from(s.value.value)),
            None => u64::from(s.value.value),
        };
        let kind = match class {
            IMAGE_SYM_CLASS_FILE => SymbolKind::File,
            IMAGE_SYM_CLASS_SECTION => SymbolKind::Section,
            _ if s.is_function() => SymbolKind::Function,
            IMAGE_SYM_CLASS_STATIC if s.value.value == 0 && s.aux_count.value > 0 => {
                SymbolKind::Section
            }
            _ => SymbolKind::NoType,
        };
        let binding = match class {
            IMAGE_SYM_CLASS_EXTERNAL => SymbolBinding::Global,
            IMAGE_SYM_CLASS_WEAK_EXTERNAL => SymbolBinding::Weak,
            IMAGE_SYM_CLASS_STATIC
            | IMAGE_SYM_CLASS_LABEL
            | IMAGE_SYM_CLASS_FILE
            | IMAGE_SYM_CLASS_SECTION
            | IMAGE_SYM_CLASS_FUNCTION => SymbolBinding::Local,
            _ => SymbolBinding::Other,
        };
        out.push(Symbol::new(
            SymbolTable::Coff,
            s.index,
            s.name.clone(),
            None,
            Va(va),
            0,
            kind,
            binding,
            sn != 0,
            s.span,
        ));
    }
    out
}

fn neutral_relocations(
    info: &PeInfo,
    symbols: &[Symbol],
    base_relocs: &[reloc::BaseReloc],
) -> Vec<Relocation> {
    let base = info.optional.image_base.value;
    let machine = info.file_header.machine.value;
    let mut out = Vec::new();
    for (table, kind, dlls, label) in [
        (
            SymbolTable::Imports,
            RelocKind::GotEntry,
            &info.imports,
            "IAT",
        ),
        (
            SymbolTable::DelayImports,
            RelocKind::PltSlot,
            &info.delay_imports,
            "delay IAT",
        ),
    ] {
        let names: Vec<String> = symbols
            .iter()
            .filter(|s| s.table == table)
            .map(Symbol::display_name)
            .collect();
        let mut index = 0u32;
        for d in dlls {
            for e in &d.entries {
                let name = names.get(index as usize).cloned();
                let rva = e.iat_va.0.wrapping_sub(base);
                out.push(Relocation {
                    table: label.to_string(),
                    offset: rva,
                    va: Some(e.iat_va),
                    section: None,
                    r_type: 0,
                    type_name: Some(if kind == RelocKind::GotEntry {
                        "IAT slot"
                    } else {
                        "delay-load IAT slot"
                    }),
                    kind,
                    symbol: Some(SymbolRef::new(table, index)),
                    symbol_name: name,
                    addend: None,
                    stored_value: e.iat_value.clone(),
                    defined_by: e.thunk.span,
                    applied_at_load: true,
                });
                index += 1;
            }
        }
    }
    for r in base_relocs {
        out.push(Relocation {
            table: "base relocations".to_string(),
            offset: r.rva,
            va: Some(Va(base.wrapping_add(r.rva))),
            section: None,
            r_type: u32::from(r.r_type),
            type_name: base_reloc_name(machine, r.r_type),
            kind: match r.r_type {
                IMAGE_REL_BASED_HIGHLOW | IMAGE_REL_BASED_DIR64 => RelocKind::Relative,
                _ => RelocKind::Other,
            },
            symbol: None,
            symbol_name: None,
            addend: None,
            stored_value: r.stored.clone(),
            defined_by: r.span,
            applied_at_load: true,
        });
    }
    out
}

fn neutral_seeds(info: &PeInfo, entry: Option<&Field<Va>>) -> Vec<Seed> {
    let base = info.optional.image_base.value;
    let va = |rva: u32| Va(base.wrapping_add(u64::from(rva)));
    let mut out = Vec::new();
    if let Some(e) = entry {
        out.push(Seed::new(e.value, None, SeedKind::Entry, e.span));
    }
    if let Some(t) = &info.tls {
        for c in &t.callbacks {
            out.push(Seed::new(c.value, None, SeedKind::TlsCallback, c.span));
        }
    }
    let thumb = info.file_header.machine.value == IMAGE_FILE_MACHINE_ARMNT;
    for f in &info.exception {
        let begin = if thumb {
            f.begin.value & !1
        } else {
            f.begin.value
        };
        let kind = if f.is_fragment() {
            SeedKind::ExceptionFragment
        } else {
            SeedKind::ExceptionTable
        };
        out.push(Seed::new(va(begin), f.end.map(va), kind, f.span));
    }
    if let Some(lc) = &info.load_config {
        for g in &lc.guard_cf_functions {
            out.push(Seed::new(va(g.rva), None, SeedKind::CfgTarget, g.span));
        }
        for h in &lc.se_handlers {
            out.push(Seed::new(va(h.value), None, SeedKind::SehHandler, h.span));
        }
    }
    out
}
