//! The format-neutral model every loader produces.

use crate::elf::ElfInfo;
use crate::mitigation::MitigationReport;
use crate::pe::PeInfo;
use fg_core::{Anomaly, ArchId, Bitness, Endian, Field, FileOffset, Perms, Span, Va};
use serde::Serialize;

/// Container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum Format {
    /// Executable and Linkable Format (Linux, BSDs, most embedded systems).
    Elf,
    /// Portable Executable (Windows, UEFI).
    Pe,
}

/// What kind of file this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum BinaryKind {
    /// Object file (`.o`): not yet linked.
    Relocatable,
    /// Executable loaded at a fixed address.
    Executable,
    /// Position-independent executable: loaded at a random address under ASLR.
    PieExecutable,
    /// Shared library.
    SharedObject,
    /// Core dump.
    Core,
    /// Recognised format, unrecognised file type.
    Unknown,
}

impl BinaryKind {
    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            BinaryKind::Relocatable => "relocatable object",
            BinaryKind::Executable => "executable (fixed address)",
            BinaryKind::PieExecutable => "PIE executable",
            BinaryKind::SharedObject => "shared object",
            BinaryKind::Core => "core dump",
            BinaryKind::Unknown => "unknown",
        }
    }
}

/// A region of the file mapped into memory at load time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Segment {
    /// Display name, e.g. `LOAD #2` (ELF) or `.text` (PE).
    pub name: String,
    /// Where the region starts in memory.
    pub va: Va,
    /// Size in memory (may exceed `file_size`; the rest is zero-filled).
    pub mem_size: u64,
    /// Where the region's bytes start in the file.
    pub file_offset: FileOffset,
    /// Number of bytes taken from the file.
    pub file_size: u64,
    /// Memory permissions.
    pub perms: Perms,
    /// The header bytes that define this segment.
    pub defined_by: Span,
}

impl Segment {
    /// Creates a segment description.
    pub fn new(
        name: String,
        va: Va,
        mem_size: u64,
        file_offset: FileOffset,
        file_size: u64,
        perms: Perms,
        defined_by: Span,
    ) -> Segment {
        Segment {
            name,
            va,
            mem_size,
            file_offset,
            file_size,
            perms,
            defined_by,
        }
    }

    /// File offset of `addr` if it lies in the file-backed part of this segment.
    pub fn file_offset_of(&self, addr: Va) -> Option<FileOffset> {
        let delta = addr.0.checked_sub(self.va.0)?;
        (delta < self.file_size)
            .then(|| self.file_offset.checked_add(delta))
            .flatten()
    }

    /// True if `addr` falls inside the segment's memory range.
    pub fn contains(&self, addr: Va) -> bool {
        addr.0 >= self.va.0 && addr.0 - self.va.0 < self.mem_size
    }
}

/// Format-specific details, kept alongside the neutral model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum FormatMetadata {
    /// ELF headers, program headers, dynamic entries.
    Elf(Box<ElfInfo>),
    /// PE headers, data directories and the tables they point at.
    Pe(Box<PeInfo>),
}

/// Everything a loader learned about a binary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct LoadedBinary {
    /// Container format.
    pub format: Format,
    /// CPU architecture.
    pub arch: ArchId,
    /// Word size.
    pub bitness: Bitness,
    /// Byte order.
    pub endian: Endian,
    /// File type.
    pub kind: BinaryKind,
    /// Program entry point, if the file has one.
    pub entry: Option<Field<Va>>,
    /// Size of the input in bytes.
    pub file_size: u64,
    /// Regions mapped into memory, in header order.
    pub segments: Vec<Segment>,
    /// Sections as named by the file's metadata (advisory: the OS loader ignores them).
    pub sections: Vec<Section>,
    /// Symbols from every symbol table, dynamic table first.
    pub symbols: Vec<Symbol>,
    /// Relocations from every relocation table, in table order.
    pub relocations: Vec<Relocation>,
    /// Shared libraries the program needs at run time, in load order.
    pub libraries: Vec<Field<String>>,
    /// Build identifier that ties the file to its debug information: the GNU build
    /// ID (ELF), or the PDB GUID and age as symbol servers spell them (PE).
    pub build_id: Option<Field<String>>,
    /// Addresses where code is declared to start (entry point, TLS callbacks,
    /// exception-table functions, init/fini arrays...), in discovery order.
    /// Symbols are not repeated here.
    pub seeds: Vec<Seed>,
    /// Exploit-mitigation verdicts with evidence.
    pub mitigations: MitigationReport,
    /// Everything malformed or unusual, most severe first.
    pub anomalies: Vec<Anomaly>,
    /// Format-specific details.
    pub metadata: FormatMetadata,
}

impl LoadedBinary {
    /// Symbols the program needs from shared libraries.
    pub fn imports(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter().filter(|s| s.is_import())
    }

    /// Symbols the file provides to others.
    pub fn exports(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter().filter(|s| s.is_export())
    }

    /// Translates a virtual address to the file offset holding its bytes, using
    /// the segments (what the OS loader maps). `None` if the address is not backed
    /// by file bytes (unmapped, or in a zero-filled tail such as `.bss`).
    pub fn file_offset_of(&self, va: Va) -> Option<FileOffset> {
        self.segments.iter().find_map(|s| s.file_offset_of(va))
    }

    /// The GOT or PLT relocation that fills the pointer slot at `va`, if any:
    /// how an indirect call through that slot is resolved to an imported name.
    pub fn slot_at(&self, va: Va) -> Option<&Relocation> {
        self.relocations.iter().find(|r| {
            r.va == Some(va) && matches!(r.kind, RelocKind::GotEntry | RelocKind::PltSlot)
        })
    }

    /// True if the file has no full symbol table (ELF `.symtab`, PE COFF symbols):
    /// only what the loader needs (dynamic symbols, imports, exports) remains.
    pub fn is_stripped(&self) -> bool {
        !self
            .symbols
            .iter()
            .any(|s| matches!(s.table, SymbolTable::Static | SymbolTable::Coff))
    }

    /// The ELF details, if this is an ELF file.
    pub fn elf(&self) -> Option<&ElfInfo> {
        match &self.metadata {
            FormatMetadata::Elf(info) => Some(info),
            _ => None,
        }
    }

    /// The PE details, if this is a PE file.
    pub fn pe(&self) -> Option<&PeInfo> {
        match &self.metadata {
            FormatMetadata::Pe(info) => Some(info),
            _ => None,
        }
    }
}

/// Safety limits applied while parsing untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum program headers parsed (real binaries have a few dozen).
    pub max_program_headers: u32,
    /// Maximum dynamic-section entries parsed.
    pub max_dynamic_entries: u32,
    /// Maximum length of the interpreter path.
    pub max_interp_len: u64,
    /// Maximum section headers parsed (object files built with
    /// `-ffunction-sections` can legitimately have tens of thousands).
    pub max_sections: u32,
    /// Maximum symbols parsed per symbol table.
    pub max_symbols: u32,
    /// Maximum length of any name read from a string table.
    pub max_name_len: u64,
    /// Maximum entries walked in a version-definition or version-need chain.
    pub max_versions: u32,
    /// Maximum relocations read per relocation table (after RELR expansion).
    pub max_relocations: u32,
    /// Maximum relocations read from an ELF file in all. Section headers may
    /// point many tables at the same bytes, so the per-table limit alone
    /// bounds nothing.
    pub max_total_relocations: u32,
    /// Maximum notes read per note segment or section.
    pub max_notes: u32,
    /// Maximum entries read from any one PE table (imports per DLL, exports,
    /// exception entries, CFG targets, TLS callbacks, debug entries...).
    pub max_table_entries: u32,
    /// Maximum DLLs read from a PE import or delay-import directory.
    pub max_libraries: u32,
    /// Maximum imports read from a PE file in all: its import and
    /// delay-import directories together. Descriptors may share one long
    /// lookup table, so the per-DLL limit alone bounds nothing.
    pub max_imports: u32,
    /// Maximum depth of the PE resource tree (Windows uses 3 levels).
    pub max_resource_depth: u32,
    /// Maximum resources (leaves) read from the PE resource tree.
    pub max_resources: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_program_headers: 65_536,
            max_dynamic_entries: 1 << 20,
            max_interp_len: 4096,
            max_sections: 1 << 20,
            max_symbols: 1 << 22,
            max_name_len: 4096,
            max_versions: 65_536,
            max_relocations: 1 << 22,
            max_total_relocations: 1 << 22,
            max_notes: 4096,
            max_table_entries: 1 << 20,
            max_libraries: 4096,
            max_imports: 1 << 16,
            max_resource_depth: 8,
            max_resources: 1 << 16,
        }
    }
}

/// Options for [`crate::load`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct LoadOptions {
    /// Parsing limits.
    pub limits: Limits,
}

impl LoadOptions {
    /// Replaces the parsing limits.
    pub fn with_limits(mut self, limits: Limits) -> LoadOptions {
        self.limits = limits;
        self
    }
}

impl Limits {
    /// Sets the maximum number of program headers.
    pub fn with_max_program_headers(mut self, n: u32) -> Limits {
        self.max_program_headers = n;
        self
    }
}

/// A named region described by the file's metadata (ELF section, PE section).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Section {
    /// Name, e.g. `.text`. Empty if the name could not be read.
    pub name: String,
    /// Memory address, if the section is loaded at run time.
    pub va: Option<Va>,
    /// Where its bytes start in the file.
    pub file_offset: FileOffset,
    /// Size in memory.
    pub size: u64,
    /// Bytes taken from the file (0 for zero-filled sections such as `.bss`).
    pub file_size: u64,
    /// Permissions the metadata claims (`read` = loaded at run time).
    pub perms: Perms,
    /// The header bytes that define this section.
    pub defined_by: Span,
}

impl Section {
    /// Creates a section description.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        va: Option<Va>,
        file_offset: FileOffset,
        size: u64,
        file_size: u64,
        perms: Perms,
        defined_by: Span,
    ) -> Section {
        Section {
            name,
            va,
            file_offset,
            size,
            file_size,
            perms,
            defined_by,
        }
    }
}

/// What a symbol names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum SymbolKind {
    /// No type information.
    NoType,
    /// Data object.
    Object,
    /// Function.
    Function,
    /// Section marker.
    Section,
    /// Source file name.
    File,
    /// Uninitialised common block.
    Common,
    /// Thread-local data.
    Tls,
    /// Function whose address is chosen at load time (GNU IFUNC).
    IndirectFunction,
    /// Anything else.
    Other,
}

/// Linkage visibility of a symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum SymbolBinding {
    /// Visible only inside the file.
    Local,
    /// Visible to other files.
    Global,
    /// Global, but may be overridden or left undefined.
    Weak,
    /// GNU unique global.
    Unique,
    /// Anything else.
    Other,
}

/// Which symbol table a symbol came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum SymbolTable {
    /// The dynamic table (`.dynsym`): what the dynamic linker uses. Survives `strip`.
    Dynamic,
    /// The full static table (`.symtab`): removed by `strip`.
    Static,
    /// PE import directory: functions and variables needed from DLLs at startup.
    Imports,
    /// PE delay-import directory: imports resolved on first use.
    DelayImports,
    /// PE export directory: what the file provides to others.
    Exports,
    /// PE COFF symbol table (kept by MinGW-style toolchains, removed by `strip`).
    Coff,
}

/// A symbol version, e.g. `GLIBC_2.2.5`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SymbolVersion {
    /// Version name.
    pub name: String,
    /// Library the version is required from (imports only), e.g. `libc.so.6`.
    pub library: Option<String>,
    /// The default version of a defined symbol (`@@`) rather than an older one (`@`).
    pub default: bool,
}

impl SymbolVersion {
    /// Creates a version.
    pub fn new(name: String, library: Option<String>, default: bool) -> SymbolVersion {
        SymbolVersion {
            name,
            library,
            default,
        }
    }
}

/// A symbol, in format-neutral form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Symbol {
    /// Table it came from.
    pub table: SymbolTable,
    /// Position in that table.
    pub index: u32,
    /// Name as stored in the file (may already contain `@VERSION` in static tables).
    pub name: String,
    /// Version from the version tables, if any.
    pub version: Option<SymbolVersion>,
    /// Address (or value for absolute symbols).
    pub va: Va,
    /// Size in bytes (0 if unknown).
    pub size: u64,
    /// What it names.
    pub kind: SymbolKind,
    /// Linkage.
    pub binding: SymbolBinding,
    /// Defined in this file (false = needed from elsewhere).
    pub defined: bool,
    /// The table entry's bytes.
    pub defined_by: Span,
    /// Library an import comes from (PE: the DLL name; ELF imports name theirs
    /// through `version`).
    pub library: Option<String>,
    /// Ordinal number (PE imports and exports).
    pub ordinal: Option<u32>,
    /// Where a forwarded export really lives, e.g. `NTDLL.RtlAllocateHeap` (PE).
    pub forwarder: Option<String>,
}

impl Symbol {
    /// Creates a symbol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table: SymbolTable,
        index: u32,
        name: String,
        version: Option<SymbolVersion>,
        va: Va,
        size: u64,
        kind: SymbolKind,
        binding: SymbolBinding,
        defined: bool,
        defined_by: Span,
    ) -> Symbol {
        Symbol {
            table,
            index,
            name,
            version,
            va,
            size,
            kind,
            binding,
            defined,
            defined_by,
            library: None,
            ordinal: None,
            forwarder: None,
        }
    }

    /// Sets the library an import comes from.
    pub fn with_library(mut self, library: Option<String>) -> Symbol {
        self.library = library;
        self
    }

    /// Sets the ordinal.
    pub fn with_ordinal(mut self, ordinal: Option<u32>) -> Symbol {
        self.ordinal = ordinal;
        self
    }

    /// Sets the forwarder string of an export.
    pub fn with_forwarder(mut self, forwarder: Option<String>) -> Symbol {
        self.forwarder = forwarder;
        self
    }

    /// Name with its version suffix as tools print it: `printf@GLIBC_2.2.5` for an
    /// import or older version, `memcpy@@GLIBC_2.14` for a default definition.
    ///
    /// PE imports are qualified by their DLL, as debuggers show them:
    /// `KERNEL32.dll!ExitProcess`, or `WS2_32.dll!#23` for an import by ordinal.
    pub fn display_name(&self) -> String {
        if matches!(self.table, SymbolTable::Imports | SymbolTable::DelayImports) {
            let lib = self.library.as_deref().unwrap_or("?");
            return match self.ordinal {
                Some(o) if self.name.is_empty() => format!("{lib}!#{o}"),
                _ => format!("{lib}!{}", self.name),
            };
        }
        if self.table == SymbolTable::Exports && self.name.is_empty() {
            return self.ordinal.map_or_else(String::new, |o| format!("#{o}"));
        }
        match &self.version {
            // Version-definition marker symbols are named after their own version.
            Some(v) if v.name == self.name => self.name.clone(),
            Some(v) if v.default => format!("{}@@{}", self.name, v.name),
            Some(v) => format!("{}@{}", self.name, v.name),
            None => self.name.clone(),
        }
    }

    /// Name without any version suffix (ELF static tables may embed `@VERSION`).
    /// PE names are returned whole: `@` is part of decorated names such as
    /// `_WinMain@16` and `?f@@YAXXZ`.
    pub fn base_name(&self) -> &str {
        match self.table {
            SymbolTable::Dynamic | SymbolTable::Static => {
                self.name.split('@').next().unwrap_or(&self.name)
            }
            _ => &self.name,
        }
    }

    /// Needed from a shared library at run time.
    pub fn is_import(&self) -> bool {
        match self.table {
            SymbolTable::Imports | SymbolTable::DelayImports => true,
            SymbolTable::Dynamic => {
                !self.defined
                    && !self.name.is_empty()
                    && matches!(self.binding, SymbolBinding::Global | SymbolBinding::Weak)
            }
            _ => false,
        }
    }

    /// Provided to other files at run time.
    pub fn is_export(&self) -> bool {
        match self.table {
            SymbolTable::Exports => true,
            SymbolTable::Dynamic => {
                self.defined
                    && !self.name.is_empty()
                    && matches!(
                        self.binding,
                        SymbolBinding::Global | SymbolBinding::Weak | SymbolBinding::Unique
                    )
            }
            _ => false,
        }
    }
}

/// What a relocation does, independent of the architecture's numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum RelocKind {
    /// Does nothing (`R_*_NONE`).
    None,
    /// Adds the load base: the slot holds a pointer into this file.
    Relative,
    /// Writes a symbol's address (plus addend) into a pointer-sized slot.
    Absolute,
    /// Fills a GOT entry with a symbol's address (`GLOB_DAT`), at startup.
    GotEntry,
    /// Fills a PLT slot with a function's address (`JUMP_SLOT`): at the first
    /// call (lazy binding) or at startup (`BIND_NOW`).
    PltSlot,
    /// Copies an imported variable's initial value into this file (`COPY`).
    Copy,
    /// Calls a resolver function and stores what it returns (`IRELATIVE`, for IFUNCs).
    IndirectRelative,
    /// Thread-local storage module, offset or descriptor.
    Tls,
    /// Anything else, e.g. the link-time relocations in object files.
    Other,
}

impl RelocKind {
    /// Plain-language description of the effect.
    pub fn meaning(self) -> &'static str {
        match self {
            RelocKind::None => "no effect",
            RelocKind::Relative => "pointer into this file, adjusted for the load address",
            RelocKind::Absolute => "pointer to a symbol",
            RelocKind::GotEntry => "GOT entry: address of a symbol, filled at startup",
            RelocKind::PltSlot => {
                "PLT slot: address of a function, filled on first call or at startup"
            }
            RelocKind::Copy => "copy of an imported variable's initial value",
            RelocKind::IndirectRelative => {
                "result of an IFUNC resolver (CPU-specific implementation)"
            }
            RelocKind::Tls => "thread-local storage",
            RelocKind::Other => "link-time fix-up",
        }
    }
}

/// Reference to an entry of one of [`LoadedBinary::symbols`]' tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct SymbolRef {
    /// Table.
    pub table: SymbolTable,
    /// Index in that table.
    pub index: u32,
}

impl SymbolRef {
    /// Creates a reference.
    pub fn new(table: SymbolTable, index: u32) -> SymbolRef {
        SymbolRef { table, index }
    }
}

/// One relocation: an instruction to patch a location when the file is loaded
/// (or linked, for object files).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Relocation {
    /// Name of the table it came from, e.g. `.rela.plt` or `DT_JMPREL`.
    pub table: String,
    /// Raw offset field: an address in loaded files, a section offset in objects.
    pub offset: u64,
    /// Address patched at run time (`None` in object files).
    pub va: Option<Va>,
    /// Section the offset is relative to (object files only).
    pub section: Option<u32>,
    /// Architecture-specific type number.
    pub r_type: u32,
    /// Type name, e.g. `R_X86_64_JUMP_SLOT`, if known.
    pub type_name: Option<&'static str>,
    /// What it does.
    pub kind: RelocKind,
    /// Symbol it refers to, if any.
    pub symbol: Option<SymbolRef>,
    /// That symbol's name with version, e.g. `printf@GLIBC_2.2.5`.
    pub symbol_name: Option<String>,
    /// Explicit addend (`RELA` tables). `REL` and `RELR` addends are implicit: they
    /// are the value already stored at the location, see `stored_value`.
    pub addend: Option<i64>,
    /// The value stored in the file at the patched location, when it is file-backed.
    /// For a lazily bound PLT slot this is the address of its PLT stub.
    pub stored_value: Option<Field<u64>>,
    /// The table entry's bytes (for `RELR`, the encoded word that produced it).
    pub defined_by: Span,
    /// Applied when the program is loaded (dynamic relocations, PE base
    /// relocations and imports, a static executable's `IRELATIVE` table).
    /// False for link-time relocations a file keeps (object files, programs
    /// linked with `--emit-relocs`): the linker already applied them, so the
    /// file's bytes are what the program sees.
    pub applied_at_load: bool,
}

/// Why an address is believed to be the start of code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum SeedKind {
    /// The program entry point from the file header.
    Entry,
    /// ELF `DT_INIT` function.
    Init,
    /// ELF `DT_FINI` function.
    Fini,
    /// Entry of an ELF `.preinit_array`.
    PreinitArray,
    /// Entry of an ELF `.init_array` (runs before `main`).
    InitArray,
    /// Entry of an ELF `.fini_array` (runs at exit).
    FiniArray,
    /// PE TLS callback: runs before the entry point, also when threads start and stop.
    TlsCallback,
    /// Start of a function described by the PE exception table (`.pdata`).
    ExceptionTable,
    /// Start of a function *fragment* in the PE exception table: code split off
    /// from another function (its unwind data chains to the parent's).
    ExceptionFragment,
    /// Valid indirect-call target from the PE Control Flow Guard table.
    CfgTarget,
    /// Exception handler registered in the PE SafeSEH table (32-bit x86).
    SehHandler,
    /// Start of a code range described by an ELF `.eh_frame` FDE, in a
    /// function's entry state. Usually a function, but also a whole PLT
    /// section or a function preceded by padding inside the range.
    UnwindTable,
    /// Start of an `.eh_frame` FDE range whose unwind state at the start is not
    /// an entry state: code split off from another function (`.cold`).
    UnwindFragment,
    /// Start of an `.eh_frame` FDE for a signal-handler trampoline (CIE
    /// augmentation `S`). By convention the range starts one instruction unit
    /// before the code, so that unwinders looking up `return address - 1`
    /// find it (glibc: `pc_begin = __restore_rt - 1`).
    UnwindSignal,
}

impl SeedKind {
    /// Plain-language description.
    pub fn meaning(self) -> &'static str {
        match self {
            SeedKind::Entry => "entry point",
            SeedKind::Init => "initialisation function (DT_INIT)",
            SeedKind::Fini => "termination function (DT_FINI)",
            SeedKind::PreinitArray => "pre-initialisation function",
            SeedKind::InitArray => "constructor, runs before main",
            SeedKind::FiniArray => "destructor, runs at exit",
            SeedKind::TlsCallback => "TLS callback, runs before the entry point",
            SeedKind::ExceptionTable => "function with unwind information",
            SeedKind::ExceptionFragment => "part of a function split off by the compiler",
            SeedKind::CfgTarget => "valid indirect-call target (Control Flow Guard)",
            SeedKind::SehHandler => "registered exception handler (SafeSEH)",
            SeedKind::UnwindTable => "code range with unwind information (.eh_frame)",
            SeedKind::UnwindSignal => {
                "signal-handler trampoline, unwind range starting just before it (.eh_frame)"
            }
            SeedKind::UnwindFragment => {
                "part of a function, unwind information starting mid-frame (.eh_frame)"
            }
        }
    }
}

/// An address where code is declared to start, with the bytes that declare it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Seed {
    /// Address of the first instruction.
    pub va: Va,
    /// End of the code (exclusive), when the declaring table records it.
    pub end: Option<Va>,
    /// Why this is believed to be code.
    pub kind: SeedKind,
    /// The bytes that declare it (table entry or header field).
    pub defined_by: Span,
}

impl Seed {
    /// Creates a seed.
    pub fn new(va: Va, end: Option<Va>, kind: SeedKind, defined_by: Span) -> Seed {
        Seed {
            va,
            end,
            kind,
            defined_by,
        }
    }
}
