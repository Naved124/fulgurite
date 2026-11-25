// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Cross-references (design §4.1 `Xref`): which instructions and data words
//! refer to which addresses, and how.
//!
//! A projection of the CFG, like [`Cfg`] itself: only the instructions of
//! recovered blocks are read, so every reference comes from bytes accepted as
//! code. A data word counts only where a relocation says it holds a pointer,
//! or, in a file loaded at a fixed address with no relocations to say so,
//! where it holds a recovered function's entry (marked as a guess).

use crate::cfg::{Cfg, Code, Image, MIN_ABSOLUTE};
use crate::track::{Sym, Tracker};
use fg_core::Va;
use fg_facts::EdgeKind;
use fg_ir::{Access, Arch, BinOp, Effect, Flow, Mode, Value};
use fg_loader::{LoadedBinary, RelocKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a reference does with its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub enum XrefKind {
    /// A call.
    Call,
    /// An unconditional jump inside the function.
    Jump,
    /// A conditional branch, when taken.
    Branch,
    /// A jump to another function.
    TailCall,
    /// An indirect jump to one of its jump table's entries.
    Table,
    /// A memory read.
    Read,
    /// A memory write.
    Write,
    /// A memory read and write (`add [rip + x], 1`).
    ReadWrite,
    /// The address is computed or loaded as a value (`lea`, `adrp` + `add`,
    /// `mov edi, offset s`), not accessed here.
    Address,
    /// A data word holds the address.
    Pointer,
}

impl XrefKind {
    /// True for references that transfer control.
    pub fn is_code(self) -> bool {
        matches!(
            self,
            XrefKind::Call
                | XrefKind::Jump
                | XrefKind::Branch
                | XrefKind::TailCall
                | XrefKind::Table
        )
    }

    /// Short name, as listings show it.
    pub fn name(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Branch => "branch",
            XrefKind::TailCall => "tail call",
            XrefKind::Table => "table",
            XrefKind::Read => "read",
            XrefKind::Write => "write",
            XrefKind::ReadWrite => "read/write",
            XrefKind::Address => "address",
            XrefKind::Pointer => "pointer",
        }
    }
}

/// How the target was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub enum Via {
    /// The instruction's own operand: a direct target, or a PC-relative or
    /// absolute memory address.
    Operand,
    /// An immediate operand: one a relocation patches (so it is an address),
    /// or, in a file loaded at a fixed address, one that lands in the file (a
    /// guess: it may be a number).
    Immediate,
    /// A register value the block's earlier instructions built: an `adrp`
    /// page plus an offset, the GOT pointer of 32-bit PIC code.
    Register,
    /// Through a pointer that a relocation fills with an address in this
    /// file (a GOT entry, a table of pointers): the pointer's address. A
    /// call or jump through it, or an access through the register it was
    /// loaded into.
    Slot(Va),
    /// One of the entries of the jump table read at this jump.
    JumpTable,
    /// A pointer-sized data word that a relocation fills.
    Relocation,
    /// A data word holding a recovered function's entry, in a file without
    /// relocations to say it is a pointer (a guess).
    DataWord,
}

impl Via {
    /// How the target was found, in a few words.
    pub fn describe(self) -> String {
        match self {
            Via::Operand => "operand".to_string(),
            Via::Immediate => "immediate".to_string(),
            Via::Register => "register built by earlier instructions".to_string(),
            Via::Slot(s) => format!("through the pointer at {s}"),
            Via::JumpTable => "jump table entry".to_string(),
            Via::Relocation => "relocated data word".to_string(),
            Via::DataWord => "data word".to_string(),
        }
    }
}

/// One reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Xref {
    /// The referring instruction, or data word.
    pub from: Va,
    /// The address referred to.
    pub to: Va,
    /// What the reference does.
    pub kind: XrefKind,
    /// How the target was found.
    pub via: Via,
    /// The function the referring instruction belongs to (the one with the
    /// lowest entry, if blocks are shared); `None` for a data word.
    pub function: Option<Va>,
    /// False for a guess (see [`Via::Immediate`] and [`Via::DataWord`]).
    pub certain: bool,
}

/// Every reference in a file.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Xrefs {
    /// By target, then source.
    refs: Vec<Xref>,
    /// Indexes into `refs`, by source.
    by_from: Vec<u32>,
}

impl Xrefs {
    fn new(mut refs: Vec<Xref>) -> Xrefs {
        refs.sort_by_key(|r| (r.to, r.from, r.kind, r.function));
        refs.dedup_by_key(|r| (r.to, r.from, r.kind));
        let mut by_from: Vec<u32> = (0..refs.len() as u32).collect();
        by_from.sort_by_key(|&i| (refs[i as usize].from, refs[i as usize].to));
        Xrefs { refs, by_from }
    }

    /// Every reference, by target.
    pub fn all(&self) -> &[Xref] {
        &self.refs
    }

    /// The references to `va`.
    pub fn to(&self, va: Va) -> &[Xref] {
        let lo = self.refs.partition_point(|r| r.to < va);
        let hi = self.refs.partition_point(|r| r.to <= va);
        &self.refs[lo..hi]
    }

    /// The references to addresses from `start` up to (not including) `end`.
    pub fn to_range(&self, start: Va, end: Va) -> &[Xref] {
        let lo = self.refs.partition_point(|r| r.to < start);
        let hi = self.refs.partition_point(|r| r.to < end);
        &self.refs[lo..hi.max(lo)]
    }

    /// The references made by the instruction or data word at `va`.
    pub fn from(&self, va: Va) -> impl Iterator<Item = &Xref> {
        let lo = self
            .by_from
            .partition_point(|&i| self.refs[i as usize].from < va);
        self.by_from[lo..]
            .iter()
            .map(|&i| &self.refs[i as usize])
            .take_while(move |r| r.from == va)
    }

    /// Number of references.
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// True if there are none.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

/// Address ranges the file maps (whole segments, file-backed or not).
struct Mapped(Vec<(u64, u64)>);

impl Mapped {
    fn new(bin: &LoadedBinary) -> Mapped {
        let mut r: Vec<(u64, u64)> = bin
            .segments
            .iter()
            .filter(|s| s.mem_size > 0)
            .map(|s| (s.va.0, s.va.0.saturating_add(s.mem_size)))
            .collect();
        r.sort_unstable();
        Mapped(r)
    }

    fn contains(&self, va: u64) -> bool {
        let i = self.0.partition_point(|&(s, _)| s <= va);
        self.0[..i].iter().rev().any(|&(s, e)| va >= s && va < e)
    }
}

/// Finds every reference the CFG's instructions and the file's data make.
pub fn collect(bin: &LoadedBinary, file: &[u8], arch: &dyn Arch, mode: Mode, cfg: &Cfg) -> Xrefs {
    let image = Image::new(bin, file);
    let mapped = Mapped::new(bin);
    let code = Code {
        image: &image,
        arch,
        mode,
        addr_bits: match (arch.id(), mode) {
            (_, Mode::X86_16) => 16,
            (_, Mode::X86_32) | (fg_core::ArchId::X86, Mode::Native) => 32,
            _ => 64,
        },
        kept: arch.callee_saved(image.windows),
    };
    // Relocations that make a pointer into this file: site → target.
    let pointers = relocated_pointers(bin);
    let lookup = Lookup {
        mapped: &mapped,
        pointers: &pointers,
        image: &image,
        mask: if code.addr_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << code.addr_bits) - 1
        },
    };
    let mut refs = Vec::new();
    // Instruction ranges read, to leave the relocations inside them to the
    // instructions.
    let mut insn_ranges: Vec<(u64, u64)> = Vec::new();
    for (&entry, f) in &cfg.functions {
        let calls: BTreeSet<(Va, Va)> = f.calls.iter().copied().collect();
        for (&start, b) in &f.blocks {
            let mut push = |from: Va, to: Va, kind: XrefKind, via: Via, certain: bool| {
                refs.push(Xref {
                    from,
                    to,
                    kind,
                    via,
                    function: Some(entry),
                    certain,
                });
            };
            let mut t = Tracker::forgetting_integers(code.addr_bits);
            let mut va = start;
            for _ in 0..b.insns {
                let Some(bytes) = image.at(va) else { break };
                let Ok(insn) = arch.decode(bytes, va, mode) else {
                    break;
                };
                let next = insn.end();
                insn_ranges.push((va.0, next.0));
                operand_refs(&insn, arch, &mapped, &mut push);
                let relocated = pointers.range(va.0..next.0).next().is_some();
                // An immediate a relocation patches is an address.
                if let Some(v) = insn.imm {
                    if relocated && mapped.contains(v) {
                        push(va, Va(v), XrefKind::Address, Via::Immediate, true);
                    } else if !relocated
                        && image.fixed
                        && v >= MIN_ABSOLUTE
                        && mapped.contains(v)
                        && insn.mem.and_then(|m| m.addr) != Some(Va(v))
                    {
                        push(va, Va(v), XrefKind::Address, Via::Immediate, false);
                    }
                }
                let e = arch.effect(&insn);
                // The register an `add`/`sub` of an immediate reads, before it.
                let before = match &e {
                    Effect::Binary {
                        a: Value::Reg { part, .. },
                        b: Value::Imm { .. },
                        ..
                    } => t.reg(part.reg).cloned(),
                    _ => None,
                };
                // An absolute address indexed by a register (`call [8*rax +
                // table]`) is an address if a relocation patches it, a guess
                // in a file loaded at a fixed address.
                let absolute = if relocated {
                    Some(true)
                } else {
                    image.fixed.then_some(false)
                };
                if !insn.nop
                    && let Some((addr, access)) = arch.mem_addr(&insn)
                {
                    memory_refs(
                        &mut t,
                        addr,
                        access,
                        &lookup,
                        absolute,
                        |to, kind, via, certain| {
                            push(va, to, kind, via, certain);
                        },
                    );
                }
                if insn.flow.is_call() {
                    code.call(&mut t, &insn);
                } else {
                    t.step(va, &e, None);
                }
                // An address plus or minus a constant (`adrp` + `add`, the GOT
                // pointer of 32-bit PIC code): not other arithmetic, which
                // makes numbers out of addresses (their difference, a shift).
                if let Effect::Binary {
                    op: BinOp::Add | BinOp::Sub,
                    dst,
                    a: Value::Reg { .. },
                    b: Value::Imm { .. },
                    ..
                } = &e
                    && matches!(before, Some(Sym::Const(_)))
                    && let Some(&Sym::Const(a)) = t.reg(dst.reg)
                    && mapped.contains(a)
                {
                    push(va, Va(a), XrefKind::Address, Via::Register, true);
                }
                // Control flow, as the CFG resolved it.
                match insn.flow {
                    Flow::Call { target } if calls.contains(&(va, target)) => {
                        push(va, target, XrefKind::Call, Via::Operand, true);
                    }
                    Flow::Call { target } | Flow::Jump { target }
                        if va == b.last && b.succs.contains(&(target, EdgeKind::Jump)) =>
                    {
                        push(va, target, XrefKind::Jump, Via::Operand, true);
                    }
                    Flow::Jump { target }
                        if va == b.last && b.succs.contains(&(target, EdgeKind::TailCall)) =>
                    {
                        push(va, target, XrefKind::TailCall, Via::Operand, true);
                    }
                    Flow::Branch { target } if va == b.last => {
                        push(va, target, XrefKind::Branch, Via::Operand, true);
                    }
                    Flow::IndirectCall | Flow::IndirectJump => {
                        if let Some(&(slot, jump)) = f.through_slots.get(&va) {
                            for &(_, target) in f.calls.iter().filter(|c| c.0 == va) {
                                let kind = match (jump, target == entry) {
                                    (false, _) => XrefKind::Call,
                                    (true, true) => XrefKind::Jump,
                                    (true, false) => XrefKind::TailCall,
                                };
                                push(va, target, kind, Via::Slot(slot), true);
                            }
                        } else if let Some(targets) = cfg.tables.get(&va) {
                            for &target in targets {
                                push(va, target, XrefKind::Table, Via::JumpTable, true);
                            }
                        }
                    }
                    _ => {}
                }
                va = next;
            }
        }
    }
    insn_ranges.sort_unstable();
    insn_ranges.dedup();
    let in_code = |site: u64| {
        let i = insn_ranges.partition_point(|&(s, _)| s <= site);
        i > 0 && site < insn_ranges[i - 1].1
    };
    for (&site, &target) in &pointers {
        if !in_code(site) && mapped.contains(target) {
            refs.push(Xref {
                from: Va(site),
                to: Va(target),
                kind: XrefKind::Pointer,
                via: Via::Relocation,
                function: None,
                certain: true,
            });
        }
    }
    // A file loaded at a fixed address has no relocation for its own
    // pointers.
    if image.fixed {
        let skip = |at: u64| in_code(at) || pointers.contains_key(&at);
        refs.extend(entry_words(bin, file, cfg, &skip));
    }
    Xrefs::new(refs)
}

/// The instruction's memory operand, when its address is in the instruction.
fn operand_refs(
    insn: &fg_ir::Insn,
    arch: &dyn Arch,
    mapped: &Mapped,
    push: &mut impl FnMut(Va, Va, XrefKind, Via, bool),
) {
    let Some(m) = insn.mem else { return };
    let Some(a) = m.addr else { return };
    if insn.nop || m.segment_based || !mapped.contains(a.0) {
        return;
    }
    let kind = match m.access {
        // `adrp` computes a 4 KiB page, not an address: the address is the
        // pair's (a register value).
        Access::Address if arch.address_pairs() && a.0 & 0xfff == 0 => return,
        Access::Address => XrefKind::Address,
        Access::Read => XrefKind::Read,
        Access::Write => XrefKind::Write,
        Access::ReadWrite => XrefKind::ReadWrite,
        _ => return,
    };
    push(insn.va, a, kind, Via::Operand, true);
}

/// What resolving a memory operand needs.
struct Lookup<'a> {
    mapped: &'a Mapped,
    /// Relocated pointers: site → target.
    pointers: &'a BTreeMap<u64, u64>,
    image: &'a Image<'a>,
    /// Address mask for the address width.
    mask: u64,
}

/// A memory operand whose address involves a register (any access, a
/// store's included): through a register the block set to a known address
/// (`Via::Register`), through a pointer a relocation fills (`Via::Slot`), or
/// the absolute start of an array indexed by a register (`Via::Operand`;
/// `absolute` says whether such an address is taken, and how surely).
/// Operands whose whole address is in the instruction are left to
/// [`operand_refs`]. Called before the instruction's effect is applied: the
/// operand reads the registers as they were.
fn memory_refs(
    t: &mut Tracker,
    addr: fg_ir::Addr,
    access: Access,
    k: &Lookup<'_>,
    absolute: Option<bool>,
    mut push: impl FnMut(Va, XrefKind, Via, bool),
) {
    let kind = match access {
        Access::Address => XrefKind::Address,
        Access::Read => XrefKind::Read,
        Access::Write => XrefKind::Write,
        Access::ReadWrite => XrefKind::ReadWrite,
        _ => return,
    };
    match (addr.base, addr.index) {
        (None, None) => {}
        (None, Some(_)) => {
            let a = addr.disp as u64 & k.mask;
            if let Some(certain) = absolute
                && (certain || a >= MIN_ABSOLUTE)
                && k.mapped.contains(a)
            {
                push(Va(a), kind, Via::Operand, certain);
            }
        }
        (Some(_), index) => {
            if let Sym::Const(a) = t.value(&Value::Address { addr }) {
                if k.mapped.contains(a) {
                    push(Va(a), kind, Via::Register, true);
                }
                return;
            }
            // An array whose start is known, indexed by an unknown.
            let start = fg_ir::Addr {
                index: None,
                ..addr
            };
            match t.value(&Value::Address { addr: start }) {
                Sym::Const(a) if index.is_some() => {
                    if k.mapped.contains(a) {
                        push(Va(a), kind, Via::Register, true);
                    }
                }
                // A base loaded from a pointer that a relocation fills with
                // an address in this file (a GOT entry, `mov rax, [rip +
                // x@GOTPCREL]`, a table of string pointers): the address it
                // holds. Certain if the pointer cannot change after
                // relocation; in writable memory, the first value only.
                _ => {
                    let base = fg_ir::Addr {
                        index: None,
                        disp: 0,
                        ..addr
                    };
                    if let Sym::Load { addr: slot, .. } = t.value(&Value::Address { addr: base })
                        && let Sym::Const(slot) = *slot
                        && let Some(&target) = k.pointers.get(&slot)
                    {
                        let a = target.wrapping_add(addr.disp as u64) & k.mask;
                        let certain = k
                            .image
                            .trust_at(slot)
                            .is_some_and(|tr| tr != crate::cfg::Trust::Writable);
                        if k.mapped.contains(a) {
                            push(Va(a), kind, Via::Slot(Va(slot)), certain);
                        }
                    }
                }
            }
        }
    }
}

/// Relocations that write a pointer into this file: site → the address it
/// holds once relocated.
fn relocated_pointers(bin: &LoadedBinary) -> BTreeMap<u64, u64> {
    let defined: HashMap<(fg_loader::SymbolTable, u32), u64> = bin
        .symbols
        .iter()
        .filter(|s| s.defined && s.va.0 != 0)
        .map(|s| ((s.table, s.index), s.va.0))
        .collect();
    let mut out = BTreeMap::new();
    // Link-time relocations a file keeps (`--emit-relocs`) are already
    // applied: the file's bytes are the value.
    for r in bin.relocations.iter().filter(|r| r.applied_at_load) {
        let Some(site) = r.va else { continue };
        let implicit = r.stored_value.as_ref().map(|v| v.value);
        let target = match r.kind {
            // The addend, or for `REL` and PE base relocations the value in
            // the file: an address at the preferred base.
            RelocKind::Relative | RelocKind::IndirectRelative => {
                r.addend.map(|a| a as u64).or(implicit)
            }
            RelocKind::Absolute | RelocKind::GotEntry => {
                let Some(sym) = r.symbol.and_then(|s| defined.get(&(s.table, s.index))) else {
                    continue;
                };
                let addend = match r.kind {
                    RelocKind::Absolute => r.addend.map(|a| a as u64).or(implicit).unwrap_or(0),
                    _ => r.addend.map_or(0, |a| a as u64),
                };
                Some(sym.wrapping_add(addend))
            }
            _ => None,
        };
        if let Some(target) = target {
            out.insert(site.0, target);
        }
    }
    out
}

/// Aligned data words holding a recovered function's entry, in a file loaded
/// at a fixed address, outside `skip`. Only the sections' bytes are read (not
/// the file header and program headers that the first segment also maps);
/// the segments, if the file has no section headers.
fn entry_words(
    bin: &LoadedBinary,
    file: &[u8],
    cfg: &Cfg,
    skip: &dyn Fn(u64) -> bool,
) -> Vec<Xref> {
    let w: usize = match bin.bitness {
        fg_core::Bitness::Bits32 => 4,
        fg_core::Bitness::Bits64 => 8,
    };
    // (address, file offset, bytes in the file) of each data range.
    let ranges: Vec<(u64, u64, u64)> = if bin.sections.iter().any(|s| s.va.is_some()) {
        bin.sections
            .iter()
            .filter(|s| !s.perms.execute && s.file_size > 0)
            .filter_map(|s| Some((s.va?.0, s.file_offset.0, s.file_size.min(s.size))))
            .collect()
    } else {
        bin.segments
            .iter()
            .filter(|s| !s.perms.execute && s.file_size > 0)
            .map(|s| (s.va.0, s.file_offset.0, s.file_size.min(s.mem_size)))
            .collect()
    };
    let mut out = Vec::new();
    for (va, offset, len) in ranges {
        let (Ok(start), Ok(len)) = (usize::try_from(offset), usize::try_from(len)) else {
            continue;
        };
        let Some(bytes) = start.checked_add(len).and_then(|end| file.get(start..end)) else {
            continue;
        };
        // Words aligned in memory.
        let first = (w - (va % w as u64) as usize) % w;
        for (i, chunk) in bytes
            .get(first..)
            .unwrap_or(&[])
            .chunks_exact(w)
            .enumerate()
        {
            let v = chunk
                .iter()
                .rev()
                .fold(0u64, |v, &b| (v << 8) | u64::from(b));
            let at = va + (first + i * w) as u64;
            if v >= MIN_ABSOLUTE && cfg.functions.contains_key(&Va(v)) && !skip(at) {
                out.push(Xref {
                    from: Va(at),
                    to: Va(v),
                    kind: XrefKind::Pointer,
                    via: Via::DataWord,
                    function: None,
                    certain: false,
                });
            }
        }
    }
    out
}
