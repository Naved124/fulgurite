//! Disassembly listings.
//!
//! M0 produces a linear sweep of code regions, the same view as `objdump -d`, but
//! decoding restarts at every symbol and code seed, so data or padding before a
//! function cannot misalign the function itself. When an instruction runs over
//! such a start, both decodings are shown (design §8.5). Branch targets and
//! statically known memory operands are named from the symbols, PLT stubs and
//! import slots. M1 replaces the sweep with recursive descent from the seeds
//! behind the same [`Line`] type.

use crate::Session;
use fg_core::{ArchId, Va};
use fg_ir::{Arch, DecodeError, Flow, Insn, Mode, Syntax, Token, TokenKind};
use fg_loader::{BinaryKind, LoadedBinary, SeedKind, Symbol, SymbolKind, SymbolTable};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::ControlFlow;

/// What to disassemble.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Target {
    /// Every executable section (every executable segment if there are no sections).
    CodeSections,
    /// One section by name.
    Section(String),
    /// A function by symbol name, from its start to its recorded end (symbol
    /// size, exception-table entry) or else to the next label.
    Symbol(String),
    /// `count` instructions starting at `va`.
    At {
        /// First address.
        va: Va,
        /// Number of instructions.
        count: usize,
    },
    /// The address range `[start, end)`.
    Range {
        /// First address.
        start: Va,
        /// End (exclusive).
        end: Va,
    },
}

/// Listing options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Assembly syntax.
    pub syntax: Syntax,
}

impl Options {
    /// Options with the given syntax.
    pub fn with_syntax(syntax: Syntax) -> Options {
        Options { syntax }
    }
}

/// One line of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "line", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Line {
    /// Start of a region (section or segment).
    Region {
        /// Section or segment name.
        name: String,
        /// First address.
        start: Va,
        /// End (exclusive).
        end: Va,
    },
    /// Names attached to the next address.
    Label {
        /// The address.
        va: Va,
        /// Symbol names (and synthetic `name@plt` stub names), best first.
        names: Vec<String>,
        /// Why the loader believes code starts here.
        seeds: Vec<SeedKind>,
    },
    /// A decoded instruction.
    Insn(InsnLine),
    /// Bytes that do not decode.
    Bad {
        /// Address of the first byte.
        va: Va,
        /// The byte(s) skipped.
        bytes: Vec<u8>,
        /// Why.
        error: DecodeError,
    },
}

/// A decoded instruction with its display text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InsnLine {
    /// The instruction.
    pub insn: Insn,
    /// Display tokens: the instruction text, then names of its target or memory
    /// operand (`Symbol`) and the address they stand for (`Comment`).
    pub tokens: Vec<Token>,
    /// True if a label or code seed starts inside this instruction. Decoding
    /// restarts there, so the overlapping bytes are listed twice.
    pub overlaps_label: bool,
}

/// Why a listing could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisasmError {
    /// No decoder exists for this architecture yet.
    UnsupportedArch(ArchId),
    /// No section has this name.
    NoSuchSection(String),
    /// No defined symbol has this name.
    NoSuchSymbol(String),
    /// The address is not backed by file bytes.
    Unmapped(Va),
}

impl fmt::Display for DisasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DisasmError::UnsupportedArch(a) => write!(f, "no decoder for {a} yet"),
            DisasmError::NoSuchSection(s) => write!(f, "no section named {s:?}"),
            DisasmError::NoSuchSymbol(s) => write!(f, "no defined symbol named {s:?}"),
            DisasmError::Unmapped(va) => write!(f, "address {va} is not backed by file bytes"),
        }
    }
}

impl std::error::Error for DisasmError {}

/// The decoder for an architecture, if Fulgurite has one.
pub fn arch_for(id: ArchId) -> Option<&'static dyn Arch> {
    match id {
        ArchId::Aarch64 => Some(&fg_arch_arm64::ARM64),
        _ => fg_arch_x86::X86::for_arch(id).map(|a| a as &dyn Arch),
    }
}

/// Arm mapping symbols (`$x`, `$d`, `$a`, `$t`, optionally `.suffix`) mark where
/// code and data start; they are not names.
fn is_mapping_symbol(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('$')
        && matches!(chars.next(), Some('x' | 'd' | 'a' | 't'))
        && matches!(chars.next(), None | Some('.'))
}

/// A region to sweep.
struct Region {
    name: Option<String>,
    start: u64,
    end: u64,
    /// Stop after this many instructions.
    count: Option<usize>,
    /// Where `start`'s bytes are in the file, for object files: their sections
    /// are not mapped by any segment (and all start at address 0).
    file_offset: Option<u64>,
}

/// Disassembles `target` of the session's binary.
pub fn disassemble(
    session: &Session,
    target: &Target,
    options: Options,
) -> Result<Vec<Line>, DisasmError> {
    let mut out = Vec::new();
    for_each_line(session, target, options, &mut |l| {
        out.push(l);
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

/// Produces the listing of `target` one line at a time, so callers can print or
/// compare it without holding it in memory (a large library has tens of millions
/// of instructions). `sink` returns [`ControlFlow::Break`] to stop early.
pub fn for_each_line(
    session: &Session,
    target: &Target,
    options: Options,
    sink: &mut dyn FnMut(Line) -> ControlFlow<()>,
) -> Result<(), DisasmError> {
    let bin = session.binary();
    let arch = arch_for(bin.arch).ok_or(DisasmError::UnsupportedArch(bin.arch))?;
    let names = Names::build(session, arch);
    let regions = regions(bin, &names, target)?;
    // An explicit address must have bytes behind it.
    if !matches!(target, Target::CodeSections | Target::Section(_))
        && let Some(r) = regions.first()
        && bytes_at(session, r.start).is_none()
    {
        return Err(DisasmError::Unmapped(Va(r.start)));
    }
    for r in &regions {
        if sweep(session, arch, &names, r, options, sink).is_break() {
            break;
        }
    }
    Ok(())
}

fn section_region(bin: &LoadedBinary, s: &fg_loader::Section) -> Option<Region> {
    let va = s.va?.0;
    Some(Region {
        name: Some(s.name.clone()),
        start: va,
        end: va.saturating_add(s.size.min(s.file_size)),
        count: None,
        file_offset: (bin.kind == BinaryKind::Relocatable).then_some(s.file_offset.0),
    })
}

fn code_regions(bin: &LoadedBinary) -> Vec<Region> {
    let mut regions: Vec<Region> = bin
        .sections
        .iter()
        .filter(|s| s.perms.execute && s.file_size > 0)
        .filter_map(|s| section_region(bin, s))
        .collect();
    if regions.is_empty() {
        regions = bin
            .segments
            .iter()
            .filter(|s| s.perms.execute && s.file_size > 0)
            .map(|s| Region {
                name: Some(s.name.clone()),
                start: s.va.0,
                end: s.va.0.saturating_add(s.file_size.min(s.mem_size)),
                count: None,
                file_offset: None,
            })
            .collect();
    }
    // Object files keep header order (every section starts at 0).
    if bin.kind != BinaryKind::Relocatable {
        regions.sort_by_key(|r| r.start);
    }
    regions
}

fn regions(bin: &LoadedBinary, names: &Names, target: &Target) -> Result<Vec<Region>, DisasmError> {
    Ok(match target {
        Target::CodeSections => code_regions(bin),
        Target::Section(name) => {
            let s = bin
                .sections
                .iter()
                .find(|s| &s.name == name && s.va.is_some())
                .ok_or_else(|| DisasmError::NoSuchSection(name.clone()))?;
            section_region(bin, s).into_iter().collect()
        }
        Target::Symbol(name) => {
            let sym = names
                .find_symbol(bin, name)
                .ok_or_else(|| DisasmError::NoSuchSymbol(name.clone()))?;
            let start = sym.va.0;
            let end = if sym.size > 0 {
                start.saturating_add(sym.size)
            } else if let Some(end) = bin
                .seeds
                .iter()
                .find(|s| s.va.0 == start && s.end.is_some())
                .and_then(|s| s.end)
            {
                end.0
            } else {
                names
                    .labels
                    .range(start + 1..)
                    .next()
                    .map_or(u64::MAX, |(&va, _)| va)
            };
            vec![Region {
                name: None,
                start,
                end,
                count: None,
                file_offset: None,
            }]
        }
        Target::At { va, count } => vec![Region {
            name: None,
            start: va.0,
            end: u64::MAX,
            count: Some(*count),
            file_offset: None,
        }],
        Target::Range { start, end } => vec![Region {
            name: None,
            start: start.0,
            end: end.0,
            count: None,
            file_offset: None,
        }],
    })
}

/// The file bytes mapped at `va`, up to the end of its segment's file-backed part.
fn bytes_at(session: &Session, va: u64) -> Option<&[u8]> {
    let bin = session.binary();
    bin.segments.iter().find_map(|s| {
        let delta = va.checked_sub(s.va.0)?;
        if delta >= s.file_size.min(s.mem_size) {
            return None;
        }
        let start = usize::try_from(s.file_offset.0.checked_add(delta)?).ok()?;
        let end = usize::try_from(s.file_offset.0.checked_add(s.file_size)?).ok()?;
        session.bytes().get(start..end.min(session.bytes().len()))
    })
}

fn sweep(
    session: &Session,
    arch: &dyn Arch,
    names: &Names,
    r: &Region,
    options: Options,
    out: &mut dyn FnMut(Line) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if let Some(name) = &r.name {
        out(Line::Region {
            name: name.clone(),
            start: Va(r.start),
            end: Va(r.end),
        })?;
    }
    let mut va = r.start;
    let mut decoded = 0usize;
    // Object-file sections all start at 0 and their symbols are section-relative,
    // so addresses cannot name them; their listings carry no labels.
    let no_labels = BTreeMap::new();
    let labels = if r.file_offset.is_some() {
        &no_labels
    } else {
        &names.labels
    };
    let mut next_label = labels.range(va..).next().map(|(&a, _)| a);
    while va < r.end && r.count.is_none_or(|c| decoded < c) {
        while let Some(l) = next_label.filter(|&l| l <= va) {
            if l == va {
                out(names.label_line(l))?;
            }
            next_label = labels.range(l + 1..).next().map(|(&a, _)| a);
        }
        let bytes = match r.file_offset {
            Some(off) => usize::try_from(off + (va - r.start))
                .ok()
                .and_then(|o| session.bytes().get(o..)),
            None => bytes_at(session, va),
        };
        let Some(bytes) = bytes else {
            break;
        };
        let avail = usize::try_from(r.end - va).unwrap_or(usize::MAX);
        let bytes = &bytes[..bytes.len().min(avail)];
        match arch.decode(bytes, Va(va), Mode::Native) {
            Ok(insn) => {
                let end = insn.end().0;
                let overlaps_label = next_label.is_some_and(|l| l < end);
                let tokens = arch.format(&insn, options.syntax);
                let tokens = if r.file_offset.is_some() {
                    tokens
                } else {
                    names.annotate(tokens, &insn)
                };
                out(Line::Insn(InsnLine {
                    insn,
                    tokens,
                    overlaps_label,
                }))?;
                va = match next_label {
                    Some(l) if overlaps_label => l,
                    _ => end,
                };
            }
            Err(error) => {
                let n = match error {
                    DecodeError::Truncated => bytes.len(),
                    _ => arch.insn_alignment() as usize,
                }
                .clamp(1, bytes.len().max(1));
                out(Line::Bad {
                    va: Va(va),
                    bytes: bytes[..n.min(bytes.len())].to_vec(),
                    error,
                })?;
                va += n as u64;
            }
        }
        decoded += 1;
    }
    ControlFlow::Continue(())
}

/// Names of code addresses as the listing labels them: symbols, and
/// `name@plt` for ELF PLT stubs. The first label at each address.
pub(crate) fn code_labels(session: &Session, arch: &dyn Arch) -> BTreeMap<u64, String> {
    Names::build(session, arch)
        .labels
        .into_iter()
        .filter_map(|(va, (names, _))| names.into_iter().next().map(|n| (va, n)))
        .collect()
}

/// Names addresses for views other than the listing (`symbol`,
/// `symbol+offset`, an import slot's import) and finds addresses by name.
pub(crate) struct Namer(Names);

impl Namer {
    pub(crate) fn new(session: &Session, arch: &dyn Arch) -> Namer {
        Namer(Names::build(session, arch))
    }

    /// A label at `va`, the import whose slot `va` is, or `symbol+offset`.
    pub(crate) fn name(&self, va: u64) -> Option<String> {
        self.0
            .labels
            .get(&va)
            .and_then(|l| l.0.first().cloned())
            .or_else(|| self.0.slots.get(&va).map(|n| format!("{n} (slot)")))
            .or_else(|| self.0.name_of(va))
    }

    /// The address a label (`puts@plt`) or a defined symbol names.
    pub(crate) fn find(&self, bin: &LoadedBinary, name: &str) -> Option<Va> {
        self.0
            .labels
            .iter()
            .find(|(_, l)| l.0.iter().any(|n| n == name))
            .map(|(&va, _)| Va(va))
            .or_else(|| self.0.find_symbol(bin, name).map(|s| s.va))
    }
}

/// Address-to-name knowledge for one binary.
struct Names {
    /// Defined symbols with an address, sorted by address.
    symbols: Vec<Named>,
    /// Exact-address labels: names and seeds.
    labels: BTreeMap<u64, (Vec<String>, Vec<SeedKind>)>,
    /// Import slots (GOT / IAT entries) by slot address.
    slots: HashMap<u64, String>,
    /// Section ranges, to keep `sym+off` names inside one section.
    sections: Vec<(u64, u64)>,
}

struct Named {
    va: u64,
    size: u64,
    name: String,
}

/// Symbols worth naming code and data with, best first at one address.
fn rank(s: &Symbol) -> u8 {
    let kind = match s.kind {
        SymbolKind::Function | SymbolKind::IndirectFunction => 0,
        SymbolKind::Object => 1,
        _ => 2,
    };
    let table = match s.table {
        SymbolTable::Static | SymbolTable::Coff => 0,
        _ => 1,
    };
    kind * 2 + table
}

impl Names {
    fn build(session: &Session, arch: &dyn Arch) -> Names {
        let bin = session.binary();
        let mut syms: Vec<&Symbol> = bin
            .symbols
            .iter()
            .filter(|s| {
                s.defined
                    && s.va.0 != 0
                    && !s.name.is_empty()
                    && !matches!(
                        s.kind,
                        SymbolKind::Section | SymbolKind::File | SymbolKind::Tls
                    )
                    && !matches!(s.table, SymbolTable::Imports | SymbolTable::DelayImports)
                    && !is_mapping_symbol(&s.name)
            })
            .collect();
        syms.sort_by_key(|s| (s.va.0, rank(s)));
        let mut labels: BTreeMap<u64, (Vec<String>, Vec<SeedKind>)> = BTreeMap::new();
        let mut symbols = Vec::with_capacity(syms.len());
        for s in &syms {
            let name = s.display_name();
            let entry = labels.entry(s.va.0).or_default();
            if !entry.0.contains(&name) {
                entry.0.push(name.clone());
            }
            symbols.push(Named {
                va: s.va.0,
                size: s.size,
                name,
            });
        }
        let mut slots = HashMap::new();
        for r in bin.relocations.iter().filter(|r| r.applied_at_load) {
            if let (Some(va), Some(name)) = (r.va, &r.symbol_name)
                && matches!(
                    r.kind,
                    fg_loader::RelocKind::GotEntry | fg_loader::RelocKind::PltSlot
                )
            {
                slots.entry(va.0).or_insert_with(|| name.clone());
            }
        }
        // PE imports name their IAT slots directly.
        for s in &bin.symbols {
            if matches!(s.table, SymbolTable::Imports | SymbolTable::DelayImports) && s.va.0 != 0 {
                slots.entry(s.va.0).or_insert_with(|| s.display_name());
            }
        }
        // An FDE start is not always an instruction boundary: it can sit in
        // alignment padding, or one byte before its function (glibc's
        // `__restore_rt`, for unwinders that look up `return address - 1`).
        // Decoding must not restart there; CFG recovery weighs those seeds.
        for seed in bin.seeds.iter().filter(|s| {
            !matches!(
                s.kind,
                SeedKind::UnwindTable | SeedKind::UnwindFragment | SeedKind::UnwindSignal
            )
        }) {
            labels.entry(seed.va.0).or_default().1.push(seed.kind);
        }
        let sections = bin
            .sections
            .iter()
            .filter_map(|s| Some((s.va?.0, s.va?.0.saturating_add(s.size))))
            .filter(|(a, b)| a < b)
            .collect();
        let mut names = Names {
            symbols,
            labels,
            slots,
            sections,
        };
        names.add_plt_stubs(session, arch);
        names
    }

    /// Names ELF PLT stubs `name@plt` after the slot their indirect jump reads,
    /// as `objdump` does.
    fn add_plt_stubs(&mut self, session: &Session, arch: &dyn Arch) {
        let bin = session.binary();
        if bin.elf().is_none() {
            return;
        }
        let mut stubs = Vec::new();
        for s in &bin.sections {
            if !matches!(s.name.as_str(), ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
                continue;
            }
            let Some(start) = s.va.map(|v| v.0) else {
                continue;
            };
            let end = start.saturating_add(s.size.min(s.file_size));
            let mut va = start;
            // A stub starts at the first instruction that is not padding after
            // the section start or after the previous stub's final jump.
            let mut entry: Option<u64> = None;
            // AArch64 stubs load the slot address in two steps:
            // adrp x16, page; ldr x17, [x16, #off]; (add x16, ...); br x17.
            let mut pages: HashMap<u8, u64> = HashMap::new();
            let mut loaded: Option<u64> = None;
            while va < end {
                let Some(bytes) = bytes_at(session, va) else {
                    break;
                };
                let bytes = &bytes[..bytes.len().min((end - va) as usize)];
                let Ok(insn) = arch.decode(bytes, Va(va), Mode::Native) else {
                    va += 1;
                    entry = None;
                    continue;
                };
                if entry.is_none() && !insn.nop {
                    entry = Some(va);
                }
                if arch.id() == ArchId::Aarch64
                    && let Ok(word) = <[u8; 4]>::try_from(&bytes[..bytes.len().min(4)])
                {
                    let word = u32::from_le_bytes(word);
                    if let Some((reg, page)) = fg_arch_arm64::adrp(word, va) {
                        pages.insert(reg, page);
                    } else if let Some((base, off)) = fg_arch_arm64::load_offset(word)
                        && let Some(page) = pages.get(&base)
                    {
                        loaded = Some(page.wrapping_add(off));
                    }
                }
                let slot = insn.mem.and_then(|m| m.addr).map(|a| a.0).or(loaded);
                if insn.flow == Flow::IndirectJump
                    && let (Some(e), Some(slot)) = (entry, slot)
                    && let Some(name) = self.slots.get(&slot)
                {
                    let base = name.split('@').next().unwrap_or(name);
                    stubs.push((e, format!("{base}@plt")));
                }
                if insn.flow.ends_block() {
                    entry = None;
                    pages.clear();
                    loaded = None;
                }
                va = insn.end().0;
            }
        }
        for (va, name) in stubs {
            let label = self.labels.entry(va).or_default();
            if !label.0.contains(&name) {
                label.0.insert(0, name.clone());
            }
            self.symbols.push(Named { va, size: 0, name });
        }
        self.symbols.sort_by_key(|s| s.va);
    }

    fn find_symbol<'b>(&self, bin: &'b LoadedBinary, name: &str) -> Option<&'b Symbol> {
        bin.symbols
            .iter()
            .filter(|s| s.defined && s.va.0 != 0)
            .find(|s| s.name == name || s.base_name() == name || s.display_name() == name)
    }

    fn label_line(&self, va: u64) -> Line {
        let (names, seeds) = self.labels.get(&va).cloned().unwrap_or_default();
        Line::Label {
            va: Va(va),
            names,
            seeds,
        }
    }

    /// The name for `va`: a symbol at it, or `symbol+offset` inside a sized
    /// symbol or after the nearest symbol in the same section.
    fn name_of(&self, va: u64) -> Option<String> {
        let i = self.symbols.partition_point(|s| s.va <= va);
        let s = self.symbols[..i].last()?;
        // Prefer the best-ranked symbol at that exact address.
        let s = self.symbols[..i]
            .iter()
            .rev()
            .take_while(|t| t.va == s.va)
            .last()
            .unwrap_or(s);
        let off = va - s.va;
        if off == 0 {
            return Some(s.name.clone());
        }
        let inside = (s.size > 0 && off < s.size)
            || self
                .sections
                .iter()
                .any(|&(a, b)| a <= s.va && s.va < b && va < b);
        inside.then(|| format!("{}+{off:#x}", s.name))
    }

    /// Adds names after the instruction text: the target of a direct branch, the
    /// import behind an indirect slot, or the object a memory operand addresses.
    fn annotate(&self, mut tokens: Vec<Token>, insn: &Insn) -> Vec<Token> {
        if let Some(target) = insn.flow.target() {
            if let Some(name) = self.name_of(target.0) {
                tokens.push(Token::new(TokenKind::Space, " "));
                tokens.push(Token::with_value(
                    TokenKind::Symbol,
                    format!("<{name}>"),
                    target.0,
                ));
            }
            return tokens;
        }
        let Some(addr) = insn.mem.and_then(|m| m.addr) else {
            return tokens;
        };
        let name = self
            .slots
            .get(&addr.0)
            .map(|n| format!("[{n}]"))
            .or_else(|| self.name_of(addr.0).map(|n| format!("<{n}>")));
        // Architectures that print the address itself (AArch64 `adrp`, `adr`,
        // literal loads) get only the name after it.
        if tokens
            .iter()
            .any(|t| t.kind == TokenKind::Address && t.value == Some(addr.0))
        {
            if let Some(n) = name {
                tokens.push(Token::new(TokenKind::Space, " "));
                tokens.push(Token::with_value(TokenKind::Symbol, n, addr.0));
            }
            return tokens;
        }
        let pc_relative = insn.mem.is_some_and(|m| m.pc_relative);
        if pc_relative || name.is_some() {
            let mut text = String::from("  # ");
            if pc_relative {
                text.push_str(&format!("{:#x}", addr.0));
            }
            if let Some(n) = name {
                if pc_relative {
                    text.push(' ');
                }
                text.push_str(&n);
            }
            tokens.push(Token::with_value(TokenKind::Comment, text, addr.0));
        }
        tokens
    }
}
