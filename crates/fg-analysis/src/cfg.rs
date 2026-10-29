//! Recursive-descent CFG recovery (design §8.1).
//!
//! Starting from every accepted `IsFunction` fact, each function's blocks are
//! decoded by following control flow. Direct call targets become new
//! functions; a direct jump to another function's entry is a tail call. The
//! entry set grows until it stops changing, and the CFGs are rebuilt against
//! the final set, so whether a jump is a tail call never depends on discovery
//! order.
//!
//! `.eh_frame` FDEs are code ranges, not function claims (see `seeds`). An FDE
//! whose unwind state at its start is not an entry state is a split-off part
//! (`.cold`) and is never a function. After the call graph settles, every
//! entry-state FDE is promoted to a function, at its first instruction after
//! leading padding, whether or not another function jumps to it (a tail call).
//! An FDE covering a whole PLT section is stubs, not a function.
//!
//! A jump that leaves its function's own FDE range, or the only jump of a
//! thunk, is a tail call, and its target a function.
//!
//! Code addresses taken without a call, by a relocated pointer in data or an
//! address computation (`lea`), that land on code no recovered function
//! contains are functions too. In a file loaded at a fixed address, absolute
//! addresses carry no relocation: immediates (`mov edi, offset main`) count,
//! and, last of all, aligned words of data that hold the address of clean code.
//!
//! An indirect jump through a jump table (design §8.3) is followed back along
//! the path into it ([`crate::track`]): when its target depends only on an
//! index the path bounds (`cmp eax, 7; ja`, or `and eax, 7`), every entry the
//! bound allows is read, and each target becomes an `Edge` fact
//! (`cfg.tables`). Without a proven bound nothing is read. A call or jump
//! through a slot that holds one of the file's own functions (a `RELATIVE`
//! GOT entry, a library's GOT entry for its own export) is a call or tail
//! call to that function; one through an `IRELATIVE` slot (an IFUNC's choice)
//! is a tail call out, as through an import's. Where code builds addresses
//! from two instructions (AArch64 `adrp` + `add`, a PLT stub's `adrp` + `ldr` +
//! `br x17`), each block's register values are followed while it is decoded.
//!
//! A function is no-return (design §8.4) when no path from its entry reaches a
//! return: every path ends in a call or tail call to a function that never
//! returns, a trap (`ud2`, `hlt`, `brk`), or a loop with no exit (no path
//! reaches a return or leaves the function at all). Calls to
//! no-return functions end their block, so the bytes after them are not
//! decoded as a fall-through. Proving one function no-return can cut its
//! callers' paths, so this repeats with the other stages until nothing
//! changes, starting from the imports that never return by definition
//! ([`NO_RETURN`]). Anything not understood (an unresolved indirect jump,
//! undecodable bytes, a tail call to an import not in the list) may return: a
//! wrong no-return claim would hide the code after every call to it.
//!
//! Facts made here: `IsFunction` for call targets (`cfg.calls`), promoted
//! FDEs (`cfg.unwind`), pointers (`cfg.pointers`) and tail-call targets
//! (`cfg.tailcalls`), `NoReturn` (`cfg.noreturn`), and the `Edge`s of jump
//! tables (`cfg.tables`). Blocks and edges
//! are a projection ([`Cfg`]) rebuilt deterministically from the facts.

use fg_core::{Evidence, Va};
use fg_facts::{
    Claim, Confidence, EdgeKind, EvidenceKind, Fact, FactId, FactStore, Provenance, Slot, Status,
    Support, Verdict,
};
use fg_ir::{Arch, Effect, Flow, Mode};
use fg_loader::LoadedBinary;
use std::collections::{BTreeMap, BTreeSet};

/// Pass name for functions found as call targets.
pub const PASS_CALLS: &str = "cfg.calls";
/// Pass name for functions promoted from unwind entries.
pub const PASS_UNWIND: &str = "cfg.unwind";
/// Pass name for functions found through relocated pointers in data.
pub const PASS_POINTERS: &str = "cfg.pointers";
/// Pass name for functions found as tail-call targets.
pub const PASS_TAILCALLS: &str = "cfg.tailcalls";
/// Pass name for functions that never return.
pub const PASS_NORETURN: &str = "cfg.noreturn";
/// Pass name for the edges of jump tables.
pub const PASS_TABLES: &str = "cfg.tables";
/// Bumped when the passes' output for the same file changes.
pub const VERSION: u32 = 1;

/// Caller evidence listed per call-target fact; the count of the rest is given.
const MAX_CALLERS: usize = 8;
/// Fixed-point rounds before giving up (each round adds at least one function).
const MAX_ROUNDS: usize = 64;
/// Blocks followed back from an indirect jump to find its table's bound.
const MAX_PATH_BLOCKS: usize = 8;
/// Most instructions decoded for one function (a hostile file cannot make a
/// single function unbounded).
const MAX_FUNCTION_INSNS: usize = 1 << 20;

/// One basic block: `[start, end)` and where control goes next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// One past the last byte.
    pub end: Va,
    /// Address of the last instruction.
    pub last: Va,
    /// Number of instructions.
    pub insns: u32,
    /// Successors inside the function, and tail calls out of it.
    pub succs: Vec<(Va, EdgeKind)>,
    /// The block ends in an indirect jump not resolved (no bounded table:
    /// a jump through a function pointer, or a table not understood).
    pub unresolved: bool,
    /// The block ends in a jump through an import slot (GOT, IAT): a tail call
    /// to an imported function. The slot's address.
    pub import: Option<Va>,
    /// Decoding failed at `end` (invalid bytes, or bytes outside the file).
    pub bad_decode: bool,
    /// The block ends in a call that never returns.
    pub no_return_call: bool,
}

/// One recovered function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    /// Blocks by start address.
    pub blocks: BTreeMap<Va, Block>,
    /// Direct calls: (call instruction, target).
    pub calls: Vec<(Va, Va)>,
    /// Code addresses computed without a memory access (`lea`, `adr`):
    /// (instruction, address).
    pub addr_refs: Vec<(Va, Va)>,
    /// Calls and tail calls in `calls` made through a slot that holds one of
    /// this file's functions (a GOT entry): instruction → (slot, is a jump).
    pub through_slots: BTreeMap<Va, (Va, bool)>,
}

/// The CFG projection of the accepted function facts.
#[derive(Clone, Debug, Default)]
pub struct Cfg {
    /// Functions by entry.
    pub functions: BTreeMap<Va, Function>,
    /// FDE ranges treated as parts of another function: (start, owning entry).
    pub fragments: BTreeMap<Va, Va>,
    /// Functions that never return.
    pub no_return: BTreeSet<Va>,
    /// Indirect jumps resolved through a jump table: jump → targets.
    pub tables: BTreeMap<Va, Vec<Va>>,
    /// Fixed-point rounds used.
    pub rounds: usize,
}

/// Executable bytes of the file, by address.
pub(crate) struct Image<'a> {
    regions: Vec<(u64, u64, &'a [u8])>,
    /// Import slots: where the dynamic loader writes an imported function's
    /// address (ELF `JUMP_SLOT`/`GLOB_DAT`, PE IAT entries), and the slots an
    /// IFUNC resolver fills (`IRELATIVE`).
    slots: BTreeSet<Va>,
    /// The import slots of functions that never return ([`NO_RETURN`]).
    no_return_slots: BTreeSet<Va>,
    /// Slots that hold one of this file's own functions: a `RELATIVE`
    /// pointer, or a GOT entry of a symbol the file defines (a library's
    /// call to its own export). Slot → function.
    local_slots: BTreeMap<Va, Va>,
    /// Bytes of the segments that are not writable, by address: what a jump
    /// table is read from.
    rodata: Vec<(u64, u64, &'a [u8])>,
    /// Addresses a relocation with an explicit addend writes to: the file's
    /// bytes there are not the value the program sees.
    relocated: BTreeSet<u64>,
    /// Every address a relocation writes to.
    reloc_sites: BTreeSet<u64>,
    /// What `RELATIVE` relocations with an explicit addend write: address →
    /// value.
    reloc_values: BTreeMap<u64, u64>,
    /// `PT_GNU_RELRO` ranges: writable while relocations apply, read-only after.
    relro: Vec<(u64, u64)>,
    /// Bytes of the segments that are not executable, by address.
    data: Vec<(u64, u64, &'a [u8])>,
    /// True for a PE file: Microsoft's calling convention.
    pub(crate) windows: bool,
    /// True if the file is loaded at a fixed address, so code addresses in it
    /// carry no relocation: immediates and data words may be addresses.
    pub(crate) fixed: bool,
}

/// ELF `PT_GNU_RELRO`.
const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Where a value read from memory comes from, the most trustworthy first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Trust {
    /// Memory that is never writable.
    ReadOnly,
    /// Memory made read-only once relocations are applied (`.data.rel.ro`).
    Relro,
    /// Writable memory: the value is what the file starts with.
    Writable,
}

/// Below this, an immediate or a data word is taken for a number, not an
/// address, even in a file loaded at a fixed address.
pub(crate) const MIN_ABSOLUTE: u64 = 0x10000;

/// Imported functions that never return to their caller, by definition (not
/// depending on their arguments, as `error()` does). A call to one ends its
/// block; otherwise decoding would run on into whatever follows the call.
pub const NO_RETURN: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__stack_chk_fail",
    "__chk_fail",
    "__fortify_fail",
    "__libc_fatal",
    "__assert_fail",
    "__assert_perror_fail",
    "__assert_rtn",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "__cxa_call_unexpected",
    "_Unwind_Resume",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
    "ExitProcess",
    "ExitThread",
    "FreeLibraryAndExitThread",
    "_invalid_parameter_noinfo_noreturn",
];

impl<'a> Image<'a> {
    pub(crate) fn new(bin: &LoadedBinary, file: &'a [u8]) -> Image<'a> {
        let mapped = |s: &fg_loader::Segment| {
            let start = usize::try_from(s.file_offset.0).ok()?;
            let len = usize::try_from(s.file_size.min(s.mem_size)).ok()?;
            let bytes = file.get(start..start.checked_add(len)?)?;
            Some((s.va.0, bytes.len() as u64, bytes))
        };
        let regions = bin
            .segments
            .iter()
            .filter(|s| s.perms.execute && s.file_size > 0)
            .filter_map(mapped)
            .collect();
        let rodata = bin
            .segments
            .iter()
            .filter(|s| !s.perms.write && s.file_size > 0)
            .filter_map(mapped)
            .collect();
        let data = bin
            .segments
            .iter()
            .filter(|s| !s.perms.execute && s.file_size > 0)
            .filter_map(mapped)
            .collect();
        let reloc_sites = bin
            .relocations
            .iter()
            .filter(|r| r.applied_at_load)
            .filter_map(|r| r.va.map(|v| v.0))
            .collect();
        let reloc_values = bin
            .relocations
            .iter()
            .filter(|r| r.applied_at_load)
            .filter(|r| r.kind == fg_loader::RelocKind::Relative)
            .filter_map(|r| Some((r.va?.0, r.addend? as u64)))
            .collect();
        let relro = bin
            .elf()
            .map(|e| {
                e.program_headers
                    .iter()
                    .filter(|p| p.p_type.value == PT_GNU_RELRO)
                    .map(|p| {
                        (
                            p.p_vaddr.value,
                            p.p_vaddr.value.saturating_add(p.p_memsz.value),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let relocated = bin
            .relocations
            .iter()
            .filter(|r| r.applied_at_load)
            .filter(|r| r.addend.is_some())
            .filter_map(|r| r.va.map(|v| v.0))
            .collect();
        let no_return = |name: &str| NO_RETURN.contains(&name.split('@').next().unwrap_or(name));
        let code = |va: u64| {
            bin.segments
                .iter()
                .any(|s| s.perms.execute && va >= s.va.0 && va - s.va.0 < s.mem_size)
        };
        let defined: std::collections::HashMap<(fg_loader::SymbolTable, u32), Va> = bin
            .symbols
            .iter()
            .filter(|s| s.defined && s.va.0 != 0 && code(s.va.0))
            .map(|s| ((s.table, s.index), s.va))
            .collect();
        let mut local_slots = BTreeMap::new();
        let mut slots = BTreeSet::new();
        let mut no_return_slots = BTreeSet::new();
        for r in bin.relocations.iter().filter(|r| r.applied_at_load) {
            // `IRELATIVE` slots hold what an IFUNC resolver picked (`memcpy`'s
            // variant for this CPU, in a static binary): a jump through one is
            // a tail call, as through an import's.
            if !matches!(
                r.kind,
                fg_loader::RelocKind::PltSlot
                    | fg_loader::RelocKind::GotEntry
                    | fg_loader::RelocKind::IndirectRelative
            ) {
                continue;
            }
            let Some(va) = r.va else { continue };
            if let Some(&t) = r
                .symbol
                .as_ref()
                .and_then(|s| defined.get(&(s.table, s.index)))
                .filter(|_| r.kind != fg_loader::RelocKind::IndirectRelative)
            {
                local_slots.insert(va, t);
                continue;
            }
            slots.insert(va);
            if r.symbol_name.as_deref().is_some_and(no_return) {
                no_return_slots.insert(va);
            }
        }
        for r in bin.relocations.iter().filter(|r| r.applied_at_load) {
            if r.kind == fg_loader::RelocKind::Relative
                && let (Some(va), Some(t)) = (
                    r.va,
                    r.addend
                        .map(|a| a as u64)
                        .or_else(|| r.stored_value.as_ref().map(|v| v.value)),
                )
                && code(t)
            {
                local_slots.insert(va, Va(t));
            }
        }
        for s in &bin.symbols {
            if matches!(
                s.table,
                fg_loader::SymbolTable::Imports | fg_loader::SymbolTable::DelayImports
            ) && s.va.0 != 0
            {
                slots.insert(s.va);
                if no_return(&s.name) {
                    no_return_slots.insert(s.va);
                }
            }
        }
        Image {
            regions,
            slots,
            no_return_slots,
            local_slots,
            rodata,
            relocated,
            reloc_sites,
            reloc_values,
            relro,
            data,
            windows: bin.format == fg_loader::Format::Pe,
            fixed: bin.kind == fg_loader::BinaryKind::Executable
                && bin.format == fg_loader::Format::Elf,
        }
    }

    /// Whether a call to `target` never returns: `target` is a stub (a PLT entry,
    /// an import thunk) whose jump goes through the slot of a [`NO_RETURN`]
    /// import, after at most two no-op or landing-pad instructions.
    fn stub_never_returns(&self, arch: &dyn Arch, target: Va) -> bool {
        let mut va = target;
        for _ in 0..3 {
            let Some(insn) = self
                .at(va)
                .and_then(|b| arch.decode(b, va, Mode::Native).ok())
            else {
                return false;
            };
            match insn.flow {
                Flow::IndirectJump => {
                    return insn
                        .mem
                        .as_ref()
                        .and_then(|m| m.addr)
                        .is_some_and(|slot| self.no_return_slots.contains(&slot));
                }
                Flow::Next => va = Va(va.0 + insn.len()),
                _ => return false,
            }
        }
        false
    }

    /// Whether `at` starts a speculation capture loop: `pause` and `lfence`
    /// only, jumping back into itself (what follows a retpoline's call).
    fn capture_loop(&self, arch: &dyn Arch, mode: Mode, at: Va) -> bool {
        const PAUSE: &[u8] = &[0xf3, 0x90];
        const LFENCE: &[u8] = &[0x0f, 0xae, 0xe8];
        let mut va = at;
        for _ in 0..4 {
            let Some(insn) = self.at(va).and_then(|b| arch.decode(b, va, mode).ok()) else {
                return false;
            };
            match insn.flow {
                Flow::Jump { target } => return va > at && target >= at && target <= va,
                Flow::Next if matches!(insn.bytes.as_slice(), PAUSE | LFENCE) => {
                    va = Va(va.0 + insn.len());
                }
                _ => return false,
            }
        }
        false
    }

    /// Bytes from `va` to the end of its executable region.
    /// How far a word at `va` can be trusted to keep its value (see
    /// [`Trust`]); `None` outside the file's bytes.
    pub(crate) fn trust_at(&self, va: u64) -> Option<Trust> {
        let within = |&(s, n, _): &(u64, u64, &[u8])| va >= s && va - s < n;
        if self.rodata.iter().any(within) {
            Some(Trust::ReadOnly)
        } else if self.relro.iter().any(|&(s, e)| va >= s && va < e) {
            Some(Trust::Relro)
        } else if self.data.iter().any(within) {
            Some(Trust::Writable)
        } else {
            None
        }
    }

    pub(crate) fn at(&self, va: Va) -> Option<&'a [u8]> {
        self.regions.iter().find_map(|&(start, len, bytes)| {
            let d = va.0.checked_sub(start)?;
            (d < len).then(|| &bytes[d as usize..])
        })
    }

    /// True if the code at `va` starts with an instruction that decodes and is
    /// not padding (`nop`, `int3`) or a trap.
    fn starts_cleanly(&self, arch: &dyn Arch, va: Va) -> bool {
        self.at(va)
            .and_then(|b| arch.decode(b, va, Mode::Native).ok())
            .is_some_and(|i| !i.nop && !matches!(i.flow, Flow::Trap | Flow::Interrupt))
    }

    /// The little-endian value of `n` bytes at `va` as the program first
    /// sees it, and how far it can be trusted to stay: the file's bytes, or
    /// what a `RELATIVE` relocation writes there. `None` where another
    /// relocation writes (the file's bytes are not what is read).
    fn read(&self, va: u64, n: u8) -> Option<(u64, Trust)> {
        let end = va.checked_add(u64::from(n))?;
        let within = |r: &&(u64, u64, &[u8])| va >= r.0 && end <= r.0 + r.1;
        let (writable, &(start, _, bytes)) = match self.rodata.iter().find(within) {
            Some(r) => (false, r),
            None => (true, self.data.iter().find(within)?),
        };
        let trust = if !writable {
            Trust::ReadOnly
        } else if self.relro.iter().any(|&(s, e)| va >= s && end <= e) {
            Trust::Relro
        } else {
            Trust::Writable
        };
        if let Some(&v) = self.reloc_values.get(&va) {
            return (n == 8 || (n == 4 && v <= u64::from(u32::MAX))).then_some((v, trust));
        }
        if self
            .relocated
            .range(va.saturating_sub(7)..end)
            .next()
            .is_some()
        {
            return None;
        }
        let d = usize::try_from(va - start).ok()?;
        let b = bytes.get(d..d.checked_add(usize::from(n))?)?;
        Some((
            b.iter().rev().fold(0, |v, &x| (v << 8) | u64::from(x)),
            trust,
        ))
    }
}

/// Recovers the CFG of every function the store accepts, adding the functions
/// it discovers to the store, until nothing new is found.
pub fn recover(
    bin: &LoadedBinary,
    file: &[u8],
    arch: &dyn Arch,
    mode: Mode,
    store: &mut FactStore,
) -> Result<Cfg, fg_facts::StoreError> {
    let image = Image::new(bin, file);
    let plt: Vec<(u64, u64)> = bin
        .sections
        .iter()
        .filter(|s| matches!(s.name.as_str(), ".plt" | ".plt.sec" | ".plt.got"))
        .filter_map(|s| s.va.map(|v| (v.0, v.0.saturating_add(s.size))))
        .collect();
    let mut cfg = Cfg::default();
    for round in 1..=MAX_ROUNDS {
        cfg.rounds = round;
        let entries = accepted_functions(store);
        let noret = accepted_no_return(store, &entries);
        cfg.tables = accepted_tables(store);
        cfg.functions = entries
            .keys()
            .map(|&e| {
                (
                    e,
                    build(&image, arch, mode, e, &entries, &noret, &cfg.tables),
                )
            })
            .collect();
        cfg.no_return = noret.keys().copied().collect();

        // Each stage runs only once the ones before it find nothing, so that
        // a function is never judged on a call graph still growing.
        // Call targets and jump tables in the same round: neither depends on
        // the other's new facts within a round.
        let mut new_facts = call_target_facts(&image, &cfg, &entries, store);
        let (tables, retract) = jump_table_facts(&image, arch, mode, &cfg, &entries, &noret, store);
        new_facts.extend(tables);
        if !retract.is_empty() {
            for id in retract {
                store.retract(id)?;
            }
            continue;
        }
        if new_facts.is_empty() {
            new_facts = no_return_facts(&image, arch, mode, &cfg, &entries, &noret, store);
        }
        if new_facts.is_empty() {
            new_facts = fde_facts(&image, arch, mode, &cfg, &entries, &noret, &plt, store);
        }
        if new_facts.is_empty() {
            new_facts = pointer_facts(bin, &image, arch, &cfg, &entries, store, false);
        }
        if new_facts.is_empty() {
            new_facts = tail_call_facts(&image, arch, &cfg, &entries, store);
        }
        // Last, the weakest evidence: words of data that hold code addresses
        // (only in a file loaded at a fixed address). By then every jump
        // table that can be read has been, so its entries are inside a
        // function and not taken for functions.
        if new_facts.is_empty() {
            new_facts = pointer_facts(bin, &image, arch, &cfg, &entries, store, true);
        }
        if new_facts.is_empty() {
            break;
        }
        for f in new_facts {
            store.insert(f)?;
        }
    }
    cfg.fragments = fragments(&cfg, store);
    Ok(cfg)
}

/// Accepted `IsFunction` facts: entry → (fact, depth in the call-discovery
/// order). Depth orders fact inputs so that the dependency graph stays acyclic
/// when functions call each other.
fn accepted_functions(store: &FactStore) -> BTreeMap<Va, (FactId, u32)> {
    let mut out = BTreeMap::new();
    for slot in store.slots() {
        let Slot::IsFunction { entry } = *slot else {
            continue;
        };
        if let Verdict::Accepted(id) = store.resolve(slot).verdict {
            out.insert(entry, (id, depth(store, id)));
        }
    }
    out
}

/// Accepted `NoReturn` facts of accepted functions: entry → fact.
fn accepted_no_return(
    store: &FactStore,
    entries: &BTreeMap<Va, (FactId, u32)>,
) -> BTreeMap<Va, FactId> {
    entries
        .keys()
        .filter_map(
            |&entry| match store.resolve(&Slot::NoReturn { entry }).verdict {
                Verdict::Accepted(id) => Some((entry, id)),
                _ => None,
            },
        )
        .collect()
}

/// Accepted jump-table edges: jump instruction → targets.
fn accepted_tables(store: &FactStore) -> BTreeMap<Va, Vec<Va>> {
    let mut out: BTreeMap<Va, Vec<Va>> = BTreeMap::new();
    for slot in store.slots() {
        if let Slot::Edge {
            from,
            to,
            edge: EdgeKind::Indirect,
        } = *slot
            && matches!(store.resolve(slot).verdict, Verdict::Accepted(_))
        {
            out.entry(from).or_default().push(to);
        }
    }
    out
}

fn depth(store: &FactStore, id: FactId) -> u32 {
    // Inputs of call-target facts are other IsFunction facts of lower depth, so
    // this terminates; it is bounded by the number of rounds anyway.
    let mut d = 0;
    let mut cur = id;
    while let Some(f) = store.get(cur) {
        if f.provenance().pass != PASS_CALLS && f.provenance().pass != PASS_TAILCALLS {
            break;
        }
        let Some(&next) = f.provenance().inputs.first() else {
            break;
        };
        d += 1;
        cur = next;
        if d as usize > MAX_ROUNDS * 4 {
            break;
        }
    }
    d
}

/// Decodes one function by following its control flow.
fn build(
    image: &Image<'_>,
    arch: &dyn Arch,
    mode: Mode,
    entry: Va,
    entries: &BTreeMap<Va, (FactId, u32)>,
    noret: &BTreeMap<Va, FactId>,
    tables: &BTreeMap<Va, Vec<Va>>,
) -> Function {
    let mut f = Function::default();
    let pairs = arch.address_pairs();
    let kept = if pairs {
        arch.callee_saved(image.windows)
    } else {
        Vec::new()
    };
    let mut work = vec![entry];
    let mut starts: BTreeSet<Va> = BTreeSet::from([entry]);
    let mut decoded = 0usize;
    // Instruction ends seen in this function, to split a block when a later
    // branch lands inside it.
    let mut insn_at: BTreeMap<Va, Va> = BTreeMap::new();
    while let Some(start) = work.pop() {
        if f.blocks.contains_key(&start) {
            continue;
        }
        // A branch into the middle of an existing block splits it.
        if let Some((&bstart, b)) = f.blocks.range(..start).next_back()
            && start < b.end
            && insn_at.contains_key(&start)
        {
            let mut tail = b.clone();
            tail.insns = insn_at.range(start..tail.end).count() as u32;
            let head = Block {
                end: start,
                last: insn_before(&insn_at, start).unwrap_or(bstart),
                insns: insn_at.range(bstart..start).count() as u32,
                succs: vec![(start, EdgeKind::Fall)],
                unresolved: false,
                import: None,
                bad_decode: false,
                no_return_call: false,
            };
            f.blocks.insert(bstart, head);
            tail.end = tail.end.max(start);
            f.blocks.insert(start, tail);
            continue;
        }
        let mut va = start;
        let mut block = Block {
            end: start,
            last: start,
            insns: 0,
            succs: Vec::new(),
            unresolved: false,
            import: None,
            bad_decode: false,
            no_return_call: false,
        };
        // Where code builds addresses from two instructions (AArch64 `adrp`
        // + `add`, `adrp` + `ldr`), the block's register values.
        let mut regs = pairs.then(|| crate::track::Tracker::forgetting_integers(64));
        loop {
            if decoded >= MAX_FUNCTION_INSNS {
                block.bad_decode = true;
                break;
            }
            let Some(bytes) = image.at(va) else {
                block.bad_decode = true;
                break;
            };
            let Ok(insn) = arch.decode(bytes, va, mode) else {
                block.bad_decode = true;
                break;
            };
            decoded += 1;
            if let Some(m) = &insn.mem
                && m.access == fg_ir::Access::Address
                && !insn.nop
                && !m.segment_based
                && let Some(a) = m.addr
                && image.at(a).is_some()
                // `adrp` computes a 4 KiB page, not an address: the address is
                // the pair's, below.
                && !(pairs && a.0 & 0xfff == 0)
            {
                f.addr_refs.push((va, a));
            }
            // The slot a register jump or call goes through, when the block
            // loaded the register from a constant address (a PLT stub's
            // `adrp x16; ldr x17, [x16, #off]; br x17`).
            let mut computed_slot = None;
            if let Some(t) = regs.as_mut() {
                let e = arch.effect(&insn);
                if let Effect::Jump { target } = &e
                    && let crate::track::Sym::Load { addr, .. } = t.value(target)
                    && let crate::track::Sym::Const(s) = *addr
                {
                    computed_slot = Some(Va(s));
                }
                if insn.flow.is_call() {
                    t.call(&kept);
                } else {
                    t.step(va, &e, None);
                }
                if let Effect::Binary { dst, .. } = &e
                    && let Some(&crate::track::Sym::Const(a)) = t.reg(dst.reg)
                    && image.at(Va(a)).is_some()
                {
                    f.addr_refs.push((va, Va(a)));
                }
            }
            // In a file loaded at a fixed address, `mov edi, offset main`.
            if image.fixed
                && let Some(v) = insn.imm.filter(|&v| v >= MIN_ABSOLUTE)
                && image.at(Va(v)).is_some()
            {
                f.addr_refs.push((va, Va(v)));
            }
            let next = Va(va.0.wrapping_add(insn.len()));
            insn_at.insert(va, next);
            block.end = next;
            block.last = va;
            block.insns += 1;
            // A call or jump through a slot holding one of this file's functions
            // is a direct one, to that function.
            let slot = insn
                .mem
                .as_ref()
                .filter(|m| m.access == fg_ir::Access::Read)
                .and_then(|m| m.addr)
                .or(computed_slot);
            let through = slot.and_then(|slot| image.local_slots.get(&slot).map(|&t| (slot, t)));
            let mut push = |t: Va, k: EdgeKind, work: &mut Vec<Va>| {
                block.succs.push((t, k));
                if k != EdgeKind::TailCall && starts.insert(t) {
                    work.push(t);
                }
            };
            match insn.flow {
                Flow::IndirectCall
                    if slot.is_some_and(|slot| image.no_return_slots.contains(&slot)) =>
                {
                    block.no_return_call = true;
                    break;
                }
                Flow::IndirectCall if through.is_some() => {
                    let (slot, target) = through.unwrap_or_default();
                    f.calls.push((va, target));
                    f.through_slots.insert(va, (slot, false));
                    if noret.contains_key(&target) {
                        block.no_return_call = true;
                        break;
                    }
                }
                Flow::Next | Flow::Interrupt | Flow::IndirectCall => {}
                // A call to the next instruction is not a call to a function:
                // the AArch64 ABI resolves a call to an undefined weak function
                // that way, and x86 code reads its own address with it. Unless
                // a function starts there (glibc's static `_dl_start` is only
                // `call abort`, and `abort` follows it).
                Flow::Call { target } if target == next && !entries.contains_key(&target) => {}
                // A retpoline: the call only pushes a return address that the
                // target overwrites, and the code after it is a capture loop
                // that runs only speculatively. The target is this function's
                // own code, not a function.
                Flow::Call { target }
                    if !entries.contains_key(&target) && image.capture_loop(arch, mode, next) =>
                {
                    push(target, EdgeKind::Jump, &mut work);
                    push(next, EdgeKind::Fall, &mut work);
                    break;
                }
                Flow::Call { target } => {
                    f.calls.push((va, target));
                    if noret.contains_key(&target) || image.stub_never_returns(arch, target) {
                        block.no_return_call = true;
                        break;
                    }
                }
                Flow::Jump { target } => {
                    let k = if target != entry && entries.contains_key(&target) {
                        EdgeKind::TailCall
                    } else {
                        EdgeKind::Jump
                    };
                    push(target, k, &mut work);
                    break;
                }
                Flow::Branch { target } => {
                    push(target, EdgeKind::CondTaken, &mut work);
                    push(next, EdgeKind::CondNotTaken, &mut work);
                    break;
                }
                Flow::IndirectJump if through.is_some() => {
                    let (slot, target) = through.unwrap_or_default();
                    f.calls.push((va, target));
                    f.through_slots.insert(va, (slot, true));
                    let k = if target == entry {
                        EdgeKind::Jump
                    } else {
                        EdgeKind::TailCall
                    };
                    push(target, k, &mut work);
                    break;
                }
                Flow::IndirectJump => {
                    match slot {
                        Some(slot) if image.slots.contains(&slot) => block.import = Some(slot),
                        _ => match tables.get(&va) {
                            Some(targets) => {
                                for &t in targets {
                                    let k = if t != entry && entries.contains_key(&t) {
                                        EdgeKind::TailCall
                                    } else {
                                        EdgeKind::Indirect
                                    };
                                    push(t, k, &mut work);
                                }
                            }
                            None => block.unresolved = true,
                        },
                    }
                    break;
                }
                Flow::Return | Flow::Trap => break,
                // A kind of flow added later: stop rather than guess.
                _ => {
                    block.unresolved = true;
                    break;
                }
            }
            va = next;
            // Falling into another block's start ends this block.
            if starts.contains(&va) || entries.contains_key(&va) && va != entry {
                if entries.contains_key(&va) && va != entry {
                    block.succs.push((va, EdgeKind::TailCall));
                } else {
                    block.succs.push((va, EdgeKind::Fall));
                }
                break;
            }
        }
        f.blocks.insert(start, block);
    }
    f
}

/// The instruction that ends at `end`, among those decoded in a function.
fn insn_before(insn_at: &BTreeMap<Va, Va>, end: Va) -> Option<Va> {
    insn_at
        .range(..end)
        .next_back()
        .and_then(|(&a, &e)| (e == end).then_some(a))
}

/// One way a path ends without returning: (instruction, why, the `NoReturn`
/// fact it relies on).
type End = (Va, String, Option<FactId>);

/// How every path from `entry` ends, if none of them returns; `None` if one
/// may. A path that reaches something not understood (an unresolved indirect
/// jump, bytes that do not decode, a block never decoded) may return.
fn never_returns(
    image: &Image<'_>,
    arch: &dyn Arch,
    mode: Mode,
    f: &Function,
    entry: Va,
    store: &FactStore,
    noret: &BTreeMap<Va, FactId>,
) -> Option<Vec<End>> {
    // A call into the function's own code (a label inside it, or right after
    // its last block) is a stack trick: the code after such a call is not where
    // it returns (glibc's `__push___start_context` switches stacks and returns
    // from the callee). Not understood, so it may return. A call to another
    // function that starts right after this one is an ordinary call, when that
    // function is known from more than this one's calls (a symbol, an FDE
    // starting there in an entry state, other callers): the label `__push___start_context` calls is a function
    // only because of that call.
    let inside = |site: Va| {
        f.blocks
            .range(..=site)
            .next_back()
            .is_some_and(|(_, b)| site < b.end)
    };
    let known_elsewhere = |t: Va| {
        let Verdict::Accepted(id) = store.resolve(&Slot::IsFunction { entry: t }).verdict else {
            return false;
        };
        store.get(id).is_some_and(|fact| {
            let p = fact.provenance();
            p.pass != PASS_CALLS || p.insns.iter().any(|&site| !inside(site))
        }) || fde_ranges(store)
            .iter()
            .any(|&(s, _, _, mid, _)| s == t && !mid)
    };
    let calls_itself = f.calls.iter().any(|&(_, t)| {
        t != entry
            && !noret.contains_key(&t)
            && f.blocks
                .range(..t)
                .next_back()
                .is_some_and(|(_, b)| t <= b.end)
            && !known_elsewhere(t)
    });
    if calls_itself {
        return None;
    }
    let mut ends: Vec<End> = Vec::new();
    let mut seen = BTreeSet::from([entry]);
    let mut work = vec![entry];
    while let Some(start) = work.pop() {
        let b = f.blocks.get(&start)?;
        if b.unresolved || b.bad_decode {
            return None;
        }
        if b.no_return_call {
            let target = f.calls.iter().find(|c| c.0 == b.last).map(|c| c.1);
            let fact = target.and_then(|t| noret.get(&t).copied());
            let why = match (target, fact) {
                (Some(t), Some(_)) => format!("calls {t}, which never returns"),
                (Some(t), None) => format!("calls {t}, a stub for an import that never returns"),
                (None, _) => "calls an import that never returns".to_string(),
            };
            ends.push((b.last, why, fact));
            continue;
        }
        if let Some(slot) = b.import {
            if !image.no_return_slots.contains(&slot) {
                return None;
            }
            ends.push((
                b.last,
                format!("jumps through {slot} to an import that never returns"),
                None,
            ));
            continue;
        }
        if b.succs.is_empty() {
            // The block ended at a return or a trap.
            let insn = image
                .at(b.last)
                .and_then(|bytes| arch.decode(bytes, b.last, mode).ok())?;
            if !matches!(insn.flow, Flow::Trap) {
                return None;
            }
            ends.push((b.last, "traps".to_string(), None));
            continue;
        }
        for &(t, k) in &b.succs {
            if k == EdgeKind::TailCall {
                let id = noret.get(&t).copied()?;
                let how = if t == b.end {
                    "runs on into"
                } else {
                    "jumps to"
                };
                ends.push((b.last, format!("{how} {t}, which never returns"), Some(id)));
            } else if seen.insert(t) {
                work.push(t);
            }
        }
    }
    ends.sort_by_key(|e| e.0);
    Some(ends)
}

/// `NoReturn` facts for functions no path of which returns, given the
/// functions already known not to. Each one proven can cut its callers' paths,
/// so their CFGs are rebuilt and checked again until nothing more is proven;
/// the facts come out in that order, each after the ones it relies on.
fn no_return_facts(
    image: &Image<'_>,
    arch: &dyn Arch,
    mode: Mode,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    noret: &BTreeMap<Va, FactId>,
    store: &FactStore,
) -> Vec<Fact> {
    let mut known = noret.clone();
    let mut confidence: BTreeMap<FactId, Confidence> = BTreeMap::new();
    let mut rebuilt: BTreeMap<Va, Function> = BTreeMap::new();
    let mut pending: BTreeSet<Va> = cfg
        .functions
        .keys()
        .filter(|e| !known.contains_key(e))
        .copied()
        .collect();
    let mut out = Vec::new();
    while !pending.is_empty() {
        let mut proved = Vec::new();
        for &entry in &pending {
            let Some(f) = rebuilt.get(&entry).or_else(|| cfg.functions.get(&entry)) else {
                continue;
            };
            let Some(ends) = never_returns(image, arch, mode, f, entry, store, &known) else {
                continue;
            };
            let conf_of = |id: FactId| {
                confidence
                    .get(&id)
                    .copied()
                    .or_else(|| store.get(id).map(|f| f.confidence()))
            };
            if let Some(fact) = no_return_fact(entry, &ends, entries, conf_of) {
                proved.push((entry, fact.id(), fact.confidence()));
                out.push(fact);
            }
        }
        for &(entry, id, conf) in &proved {
            known.insert(entry, id);
            confidence.insert(id, conf);
        }
        // Only the callers of what was just proven can change.
        let cut: BTreeSet<Va> = proved.iter().map(|p| p.0).collect();
        pending = cfg
            .functions
            .iter()
            .filter(|(e, _)| !known.contains_key(e))
            .filter(|(_, f)| {
                f.calls.iter().any(|c| cut.contains(&c.1))
                    || f.blocks
                        .values()
                        .flat_map(|b| &b.succs)
                        .any(|&(t, k)| k == EdgeKind::TailCall && cut.contains(&t))
            })
            .map(|(&e, _)| e)
            .collect();
        for &e in &pending {
            rebuilt.insert(e, build(image, arch, mode, e, entries, &known, &cfg.tables));
        }
    }
    out
}

/// The `NoReturn` fact for `entry`, whose paths end as `ends`.
fn no_return_fact(
    entry: Va,
    ends: &[End],
    entries: &BTreeMap<Va, (FactId, u32)>,
    conf_of: impl Fn(FactId) -> Option<Confidence>,
) -> Option<Fact> {
    let w = Confidence::new(0.95)?;
    let mut inputs = vec![entries.get(&entry)?.0];
    for &(_, _, id) in ends {
        if let Some(id) = id
            && !inputs.contains(&id)
        {
            inputs.push(id);
        }
    }
    let confs: Vec<Confidence> = inputs
        .iter()
        .map(|&id| conf_of(id))
        .collect::<Option<_>>()?;
    let mut ev: Vec<Support> = ends
        .iter()
        .take(MAX_CALLERS)
        .map(|(at, why, _)| {
            Support::new(EvidenceKind::Flow, Evidence::new(format!("{at} {why}")), w).at(*at)
        })
        .collect();
    if ends.len() > MAX_CALLERS
        && let Some(last) = ev.last_mut()
    {
        last.evidence.text += &format!(" (and {} more paths)", ends.len() - MAX_CALLERS);
    }
    if ends.is_empty() {
        ev.push(
            Support::new(
                EvidenceKind::Flow,
                Evidence::new(
                    "no path from the entry reaches a return or leaves the function".to_string(),
                ),
                w,
            )
            .at(entry),
        );
    }
    let mut prov = Provenance::new(PASS_NORETURN, VERSION);
    prov.inputs = inputs;
    prov.insns = ends.iter().take(MAX_CALLERS).map(|e| e.0).collect();
    Fact::new(
        Claim::NoReturn { entry },
        Status::Inferred,
        Confidence::derived(confs, w),
        prov,
        ev,
    )
    .ok()
}

/// New `IsFunction` facts for direct call targets that are not functions yet.
fn call_target_facts(
    image: &Image<'_>,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    store: &FactStore,
) -> Vec<Fact> {
    let mut callers: BTreeMap<Va, Vec<(u32, Va, Va)>> = BTreeMap::new();
    for (&fentry, f) in &cfg.functions {
        let d = entries.get(&fentry).map_or(0, |e| e.1);
        for &(site, target) in &f.calls {
            // A call to memory that is not code (a weak undefined function linked
            // to 0, a corrupt target) does not make a function.
            if !entries.contains_key(&target) && image.at(target).is_some() {
                callers.entry(target).or_default().push((d, site, fentry));
            }
        }
    }
    callers
        .into_iter()
        .filter_map(|(target, mut cs)| {
            // Strongest, shallowest callers first; inputs only from callers of
            // the smallest depth keep the dependency graph acyclic.
            cs.sort();
            let min_d = cs[0].0;
            let mut inputs = Vec::new();
            let mut confs = Vec::new();
            let mut ev = Vec::new();
            for &(d, site, fentry) in cs.iter().take(MAX_CALLERS) {
                let (id, _) = entries[&fentry];
                if d == min_d && !inputs.contains(&id) {
                    inputs.push(id);
                    confs.push(store.get(id)?.confidence());
                }
                let how = match cfg.functions[&fentry].through_slots.get(&site) {
                    Some(&(slot, false)) => format!("called through the slot at {slot}"),
                    Some(&(slot, true)) => format!("jumped to through the slot at {slot}"),
                    None => "called".to_string(),
                };
                ev.push(
                    Support::new(
                        EvidenceKind::Flow,
                        Evidence::new(format!("{how} from {site} in the function at {fentry}")),
                        store.get(id)?.confidence(),
                    )
                    .at(site),
                );
            }
            if cs.len() > MAX_CALLERS
                && let Some(last) = ev.last_mut()
            {
                last.evidence.text += &format!(" (and {} more calls)", cs.len() - MAX_CALLERS);
            }
            // §8.2: 0.95 × the caller's confidence.
            let strongest = confs.into_iter().max().unwrap_or(Confidence::ZERO);
            let conf = Confidence::derived([strongest], Confidence::new(0.95)?);
            let mut prov = Provenance::new(PASS_CALLS, VERSION);
            prov.inputs = inputs;
            prov.insns = cs.iter().take(MAX_CALLERS).map(|c| c.1).collect();
            Fact::new(
                Claim::IsFunction { entry: target },
                Status::Inferred,
                conf,
                prov,
                ev,
            )
            .ok()
        })
        .collect()
}

/// `Edge` facts for indirect jumps through a jump table whose index is
/// bounded on the way to the jump (design §8.3). Only a proven bound reads a
/// table: without one, the entries past its end would be read as code. Every
/// entry must be code of this file, or none is taken.
fn jump_table_facts(
    image: &Image<'_>,
    arch: &dyn Arch,
    mode: Mode,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    noret: &BTreeMap<Va, FactId>,
    store: &FactStore,
) -> (Vec<Fact>, Vec<FactId>) {
    let code = Code {
        image,
        arch,
        mode,
        addr_bits: match (arch.id(), mode) {
            (_, Mode::X86_16) => 16,
            (_, Mode::X86_32) | (fg_core::ArchId::X86, Mode::Native) => 32,
            _ => 64,
        },
        kept: arch.callee_saved(image.windows),
    };
    let align = arch.insn_alignment().max(1);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut retract = Vec::new();
    let distinct = |targets: &[u64]| -> BTreeSet<Va> { targets.iter().map(|&t| Va(t)).collect() };
    for (&fentry, f) in &cfg.functions {
        let preds = predecessors(f);
        for (&start, b) in &f.blocks {
            // A table read earlier is read again on today's CFG: code found
            // since (its own cases included) may join the path past the bound.
            // If the table no longer reads the same, its edges are withdrawn;
            // the code that broke the path stays, so it is not read again.
            if let Some(accepted) = cfg.tables.get(&b.last) {
                if !seen.insert(b.last) {
                    continue;
                }
                let now =
                    read_table(&code, f, fentry, &preds, start).map(|(t, _)| distinct(&t.targets));
                if now.as_ref() != Some(&accepted.iter().copied().collect()) {
                    for &to in accepted {
                        let slot = Slot::Edge {
                            from: b.last,
                            to,
                            edge: EdgeKind::Indirect,
                        };
                        if let Verdict::Accepted(id) = store.resolve(&slot).verdict
                            && store
                                .get(id)
                                .is_some_and(|f| f.provenance().pass == PASS_TABLES)
                        {
                            retract.push(id);
                        }
                    }
                }
                continue;
            }
            if !b.unresolved || b.bad_decode || !seen.insert(b.last) {
                continue;
            }
            let Some((table, trust)) = read_table(&code, f, fentry, &preds, start) else {
                continue;
            };
            if !table
                .targets
                .iter()
                .all(|&t| t.is_multiple_of(align) && image.at(Va(t)).is_some())
            {
                continue;
            }
            // Read again with the cases in the function: a case that jumps back
            // into the path past the bound check would bypass it.
            let mut tentative = cfg.tables.clone();
            tentative.insert(b.last, distinct(&table.targets).into_iter().collect());
            let with_cases = build(image, arch, mode, fentry, entries, noret, &tentative);
            let again = block_ending_at(&with_cases, b.last).and_then(|s| {
                read_table(&code, &with_cases, fentry, &predecessors(&with_cases), s)
            });
            if again.map(|(t, _)| t.targets) != Some(table.targets.clone()) {
                continue;
            }
            let Some(fn_fact) = entries.get(&fentry).and_then(|e| store.get(e.0)) else {
                continue;
            };
            let mut by_target: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            for (i, &t) in table.targets.iter().enumerate() {
                by_target.entry(t).or_default().push(i as u64);
            }
            let what = match table.table {
                Some((at, bytes)) => format!(
                    "the jump table at {} ({} entries of {bytes} bytes)",
                    Va(at),
                    table.targets.len()
                ),
                None => format!("a computed jump ({} cases)", table.targets.len()),
            };
            for (t, idx) in by_target {
                let mut list: Vec<String> =
                    idx.iter().take(MAX_CALLERS).map(u64::to_string).collect();
                if idx.len() > MAX_CALLERS {
                    list.push(format!("and {} more", idx.len() - MAX_CALLERS));
                }
                let text = format!(
                    "{} {} of {what}; the index is at most {}, by {}{}",
                    if idx.len() == 1 { "entry" } else { "entries" },
                    list.join(", "),
                    table.bound.max,
                    table.bound.at,
                    match trust {
                        Trust::ReadOnly => "",
                        Trust::Relro => "; the table is read-only once relocated",
                        Trust::Writable => {
                            "; the table is in writable memory: these are the entries the file starts with"
                        }
                    }
                );
                let ev = Support::new(
                    EvidenceKind::Flow,
                    Evidence::new(text),
                    fn_fact.confidence(),
                )
                .at(b.last);
                // A writable table may be changed while the program runs.
                let Some(w) = Confidence::new(if trust == Trust::Writable { 0.4 } else { 0.95 })
                else {
                    continue;
                };
                let mut prov = Provenance::new(PASS_TABLES, VERSION);
                prov.inputs = vec![fn_fact.id()];
                prov.insns = vec![table.bound.at, b.last];
                if let Ok(fact) = Fact::new(
                    Claim::Edge {
                        from: b.last,
                        to: Va(t),
                        edge: EdgeKind::Indirect,
                    },
                    Status::Inferred,
                    Confidence::derived([fn_fact.confidence()], w),
                    prov,
                    vec![ev],
                ) {
                    out.push(fact);
                }
            }
        }
    }
    (out, retract)
}

/// What following values through code needs.
pub(crate) struct Code<'a> {
    pub(crate) image: &'a Image<'a>,
    pub(crate) arch: &'a dyn Arch,
    pub(crate) mode: Mode,
    /// Address width.
    pub(crate) addr_bits: u8,
    /// Registers a call preserves.
    pub(crate) kept: Vec<fg_ir::Reg>,
}

impl Code<'_> {
    /// A call: the registers it does not preserve become unknown. A call to
    /// a PC thunk (`__x86.get_pc_thunk.bx`: `mov ebx, [esp]; ret`) sets its
    /// register to the return address, which 32-bit PIC code then turns into
    /// the GOT's address.
    pub(crate) fn call(&self, t: &mut crate::track::Tracker, insn: &fg_ir::Insn) {
        // `call next; pop r` (clang's 32-bit PIC) calls nothing: the `pop`
        // loads its own address.
        if let Flow::Call { target } = insn.flow
            && target == insn.end()
            && let Some(r) = self.pops_into(target)
        {
            t.assume_after_next(r, crate::track::Known::Const(target.0));
            return;
        }
        t.call(&self.kept);
        if let Flow::Call { target } = insn.flow
            && let Some(r) = self.pc_thunk(target)
        {
            t.assume(r, crate::track::Known::Const(insn.end().0));
        }
    }

    /// The register a `pop` at `at` loads.
    fn pops_into(&self, at: Va) -> Option<fg_ir::Reg> {
        let insn = self.arch.decode(self.image.at(at)?, at, self.mode).ok()?;
        let text = self.arch.format(&insn, fg_ir::Syntax::Intel);
        let mnemonic = text.iter().find(|t| t.kind == fg_ir::TokenKind::Mnemonic)?;
        if mnemonic.text != "pop" {
            return None;
        }
        let sp = self.arch.stack_pointer()?;
        match self.arch.effect(&insn) {
            Effect::Other {
                writes, all: false, ..
            } if writes.len() == 2 && writes.contains(&sp) => writes.into_iter().find(|&r| r != sp),
            _ => None,
        }
    }

    /// The register a PC thunk at `at` loads its return address into.
    fn pc_thunk(&self, at: Va) -> Option<fg_ir::Reg> {
        let sp = self.arch.stack_pointer()?;
        let first = self.arch.decode(self.image.at(at)?, at, self.mode).ok()?;
        let Effect::Move {
            dst,
            src:
                fg_ir::Value::Load {
                    addr:
                        fg_ir::Addr {
                            base: Some(base),
                            index: None,
                            disp: 0,
                        },
                    ..
                },
        } = self.arch.effect(&first)
        else {
            return None;
        };
        let next = first.end();
        let ret = self
            .arch
            .decode(self.image.at(next)?, next, self.mode)
            .ok()?;
        (base == sp && ret.flow == Flow::Return).then_some(dst.reg)
    }
}

/// Each block's predecessors inside the function.
fn predecessors(f: &Function) -> BTreeMap<Va, Vec<(Va, EdgeKind)>> {
    let mut preds: BTreeMap<Va, Vec<(Va, EdgeKind)>> = BTreeMap::new();
    for (&s, b) in &f.blocks {
        for &(t, k) in &b.succs {
            if k != EdgeKind::TailCall {
                preds.entry(t).or_default().push((s, k));
            }
        }
    }
    preds
}

/// The start of the block whose last instruction is at `last`.
fn block_ending_at(f: &Function, last: Va) -> Option<Va> {
    f.blocks
        .iter()
        .find(|(_, b)| b.last == last)
        .map(|(&s, _)| s)
}

/// The jump table behind the indirect jump that ends the block at `jump`,
/// followed along the path into it: back through every block with a single
/// predecessor in the function.
fn read_table(
    code: &Code<'_>,
    f: &Function,
    entry: Va,
    preds: &BTreeMap<Va, Vec<(Va, EdgeKind)>>,
    jump: Va,
) -> Option<(crate::track::Table, Trust)> {
    // (block, the edge the path leaves it by), from the earliest block.
    let mut path = vec![(jump, None)];
    while path.len() < MAX_PATH_BLOCKS {
        let cur = path[path.len() - 1].0;
        let Some(&[(p, k)]) = preds.get(&cur).map(Vec::as_slice) else {
            break;
        };
        if path.iter().any(|&(s, _)| s == p) {
            break;
        }
        path.push((p, Some(k)));
    }
    path.reverse();
    let tracker = |general: bool| {
        if general {
            crate::track::Tracker::forgetting_integers(code.addr_bits)
        } else {
            crate::track::Tracker::new(code.addr_bits)
        }
    };
    // Exactly, then with integer constants forgotten: the only path known may
    // be a loop's first iteration, before the cases that loop back are found.
    // And what was done before the path started still counts when it holds
    // on every way in: a table's address loaded before a loop the jump is in,
    // or an index written as 32 bits (so `cmp ebx, 45` bounds `rbx`).
    follow(code, f, &path, tracker(false)).or_else(|| {
        let mut t = tracker(true);
        for (r, k) in known_at(code, f, entry, path[0].0) {
            t.assume(r, k);
        }
        follow(code, f, &path, t)
    })
}

/// Follows `path` (blocks, and the edge each is left by) with `t`, up to the
/// indirect jump that ends it, and reads its table.
fn follow(
    code: &Code<'_>,
    f: &Function,
    path: &[(Va, Option<EdgeKind>)],
    mut t: crate::track::Tracker,
) -> Option<(crate::track::Table, Trust)> {
    let Code {
        image, arch, mode, ..
    } = *code;
    for &(start, leave) in path {
        let b = f.blocks.get(&start)?;
        let mut va = start;
        while va < b.end {
            let insn = arch.decode(image.at(va)?, va, mode).ok()?;
            let e = arch.effect(&insn);
            if va == b.last && leave.is_none() {
                let Effect::Jump { target } = e else {
                    return None;
                };
                let target = t.value(&target);
                let trust = std::cell::Cell::new(Trust::ReadOnly);
                let read = |a, n| {
                    image.read(a, n).map(|(v, tr)| {
                        trust.set(trust.get().max(tr));
                        v
                    })
                };
                return t.table(&target, &read).map(|tb| (tb, trust.get()));
            }
            let taken = match leave {
                Some(EdgeKind::CondTaken) if va == b.last => Some(true),
                Some(EdgeKind::CondNotTaken) if va == b.last => Some(false),
                _ => None,
            };
            if insn.flow.is_call() {
                code.call(&mut t, &insn);
            } else {
                t.step(va, &e, taken);
            }
            va = insn.end();
        }
    }
    None
}

/// What is known of each register on every path from the function's entry to
/// the block at `at`: the same address, or a value that fits in fewer bits (a
/// forward pass to a fixed point: a fact stays at a block only while every
/// predecessor agrees). Integer constants are left out, as by
/// [`crate::track::Tracker::forgetting_integers`].
fn known_at(
    code: &Code<'_>,
    f: &Function,
    entry: Va,
    at: Va,
) -> BTreeMap<fg_ir::Reg, crate::track::Known> {
    let Code {
        image, arch, mode, ..
    } = *code;
    let mut ins: BTreeMap<Va, BTreeMap<fg_ir::Reg, crate::track::Known>> =
        BTreeMap::from([(entry, BTreeMap::new())]);
    let mut work = vec![entry];
    let mut steps = 0;
    while let Some(start) = work.pop() {
        steps += 1;
        if steps > 64 * f.blocks.len() {
            return BTreeMap::new();
        }
        let Some(b) = f.blocks.get(&start) else {
            continue;
        };
        let mut t = crate::track::Tracker::forgetting_integers(code.addr_bits);
        for (&r, &k) in &ins[&start] {
            t.assume(r, k);
        }
        let mut va = start;
        while va < b.end {
            let Some(insn) = image.at(va).and_then(|x| arch.decode(x, va, mode).ok()) else {
                break;
            };
            if insn.flow.is_call() {
                code.call(&mut t, &insn);
            } else {
                t.step(va, &arch.effect(&insn), None);
            }
            va = insn.end();
        }
        let out = t.known();
        for &(s, k) in &b.succs {
            if k == EdgeKind::TailCall {
                continue;
            }
            let changed = match ins.get_mut(&s) {
                None => {
                    ins.insert(s, out.clone());
                    true
                }
                Some(cur) => {
                    let before = cur.clone();
                    *cur = cur
                        .iter()
                        .filter_map(|(&r, &k)| Some((r, k.meet(*out.get(&r)?)?)))
                        .collect();
                    *cur != before
                }
            };
            if changed {
                work.push(s);
            }
        }
    }
    ins.remove(&at).unwrap_or_default()
}

/// Every address some recovered function reaches as a block.
fn reached_blocks(cfg: &Cfg) -> BTreeMap<Va, Va> {
    let mut out = BTreeMap::new();
    for (&e, f) in &cfg.functions {
        for &b in f.blocks.keys() {
            if b != e {
                out.entry(b).or_insert(e);
            }
        }
    }
    out
}

/// Accepted FDE code ranges (`IsCode` facts with FDE evidence from the seed
/// pass): (start, end, fact, starts mid-frame, signal trampoline).
fn fde_ranges(store: &FactStore) -> Vec<(Va, Va, FactId, bool, bool)> {
    let table = fg_loader::SeedKind::UnwindTable.meaning();
    let fragment = fg_loader::SeedKind::UnwindFragment.meaning();
    let signal = fg_loader::SeedKind::UnwindSignal.meaning();
    store
        .slots()
        .filter_map(|slot| {
            let Slot::IsCode { start, end } = *slot else {
                return None;
            };
            let Verdict::Accepted(id) = store.resolve(slot).verdict else {
                return None;
            };
            let texts: Vec<&str> = store
                .facts_in(slot)
                .filter(|f| f.provenance().pass == crate::seeds::PASS)
                .flat_map(|f| f.evidence().iter().map(|e| e.evidence.text.as_str()))
                .collect();
            let mid = texts.contains(&fragment);
            let sig = texts.contains(&signal);
            (mid || sig || texts.contains(&table)).then_some((start, end, id, mid, sig))
        })
        .collect()
}

/// Promotes every entry-state FDE to a function at its first instruction after
/// leading padding. Split-off parts start mid-frame and are left out, so a
/// function reached only by a tail-call jump is still found.
///
/// A split-off part of a function that has no frame at the jump also starts
/// in an entry state, exactly like a tail-called function. Such a part is
/// told apart by what it does: it never returns (it is the path to `abort` or
/// a trap) and one other function jumps to it, with no fall-through into it.
/// Compilers do not tail-call a function that never returns (the call is not
/// followed by a return), so that jump is a branch to the function's own cold
/// path.
#[allow(clippy::too_many_arguments)]
fn fde_facts(
    image: &Image<'_>,
    arch: &dyn Arch,
    mode: Mode,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    noret: &BTreeMap<Va, FactId>,
    plt: &[(u64, u64)],
    store: &FactStore,
) -> Vec<Fact> {
    // (range start, range end, fact, padding skipped, first instruction)
    let mut candidates = Vec::new();
    for (start, end, id, mid_frame, signal) in fde_ranges(store) {
        // A range that starts mid-frame is part of another function; a whole
        // PLT section is stubs.
        if mid_frame || plt.contains(&(start.0, end.0)) {
            continue;
        }
        // Skip leading padding to the first real instruction.
        let mut va = start;
        let mut pad = 0u64;
        while va < end {
            let Some(insn) = image.at(va).and_then(|b| arch.decode(b, va, mode).ok()) else {
                break;
            };
            if !insn.nop {
                break;
            }
            pad += insn.len();
            va = Va(va.0 + insn.len());
        }
        // A signal trampoline's FDE starts one instruction unit early by
        // convention. On AArch64 that unit is a `nop`, skipped above; on x86
        // glibc defines `pc_begin = __restore_rt - 1`, a byte that can sit
        // inside the padding before it.
        if signal && va == start && arch.insn_alignment() == 1 {
            va = Va(start.0 + 1);
            pad = 1;
        }
        if va >= end || entries.contains_key(&va) {
            continue;
        }
        candidates.push((start, end, id, pad, va));
    }
    let built: BTreeMap<Va, Function> = candidates
        .iter()
        .map(|c| {
            (
                c.4,
                build(image, arch, mode, c.4, entries, noret, &cfg.tables),
            )
        })
        .collect();
    // Who jumps to each candidate, and whether anything falls into it.
    let mut jumpers: BTreeMap<Va, BTreeSet<Va>> = BTreeMap::new();
    let mut fallen_into: BTreeSet<Va> = BTreeSet::new();
    for (&e, f) in cfg.functions.iter().chain(&built) {
        for (&s, b) in &f.blocks {
            // A block that runs over the start falls into it. A block whose
            // first bytes do not decode ends where it starts, and runs over
            // nothing.
            use std::ops::Bound::Excluded;
            if s < b.end {
                fallen_into.extend(built.range((Excluded(s), Excluded(b.end))).map(|(&t, _)| t));
            }
            for &(t, k) in &b.succs {
                if t == e || !built.contains_key(&t) {
                    continue;
                }
                match k {
                    // A jump table's entry is a jump too.
                    EdgeKind::Jump | EdgeKind::CondTaken | EdgeKind::Indirect => {
                        jumpers.entry(t).or_default().insert(e);
                    }
                    _ => {
                        fallen_into.insert(t);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for (start, end, id, pad, va) in candidates {
        let split_off = !fallen_into.contains(&va)
            && jumpers.get(&va).is_some_and(|j| j.len() == 1)
            && never_returns(image, arch, mode, &built[&va], va, store, noret).is_some();
        if split_off {
            continue;
        }
        let text = if pad == 0 {
            format!("unwind information (.eh_frame) covers {start}..{end}")
        } else {
            format!(
                "unwind information (.eh_frame) covers {start}..{end}; the first instruction \
                 follows {pad} bytes of padding"
            )
        };
        let ev = Support::new(
            EvidenceKind::Format,
            Evidence::new(text),
            Confidence::new(0.9).unwrap_or(Confidence::ZERO),
        )
        .at(start);
        let mut prov = Provenance::new(PASS_UNWIND, VERSION);
        prov.inputs = vec![id];
        prov.insns = vec![va];
        if let Ok(f) = Fact::new(
            Claim::IsFunction { entry: va },
            Status::Inferred,
            Confidence::new(0.9).unwrap_or(Confidence::ZERO),
            prov,
            vec![ev],
        ) {
            out.push(f);
        }
    }
    out
}

/// Where a code address was found.
enum PtrSource<'a> {
    /// A relocation the dynamic loader applies.
    Reloc(&'a fg_loader::Relocation),
    /// An instruction computing it: (instruction, function).
    Code(Va, Va),
    /// A word of data holding it, in a file loaded at a fixed address.
    Data(Va),
}

/// Code addresses taken without being called: those the dynamic loader writes
/// into data (`RELATIVE` relocations, and the resolvers `IRELATIVE` relocations
/// call), and those instructions compute without reading memory (`lea`, as
/// `_start` does to pass `main` to `__libc_start_main`). Ones that land on code
/// no recovered function contains are functions: function pointers, vtable
/// entries, IFUNC resolvers, callbacks. An address inside a recovered
/// function (a computed-goto label, a landing pad), inside a split-off part,
/// or strictly inside any FDE's range is not a function.
fn pointer_facts(
    bin: &LoadedBinary,
    image: &Image<'_>,
    arch: &dyn Arch,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    store: &FactStore,
    data_words: bool,
) -> Vec<Fact> {
    let mut covered: Vec<(Va, Va)> = cfg
        .functions
        .values()
        .flat_map(|f| f.blocks.iter().map(|(&s, b)| (s, b.end)))
        .collect();
    covered.sort();
    let inside = |va: Va| {
        let i = covered.partition_point(|&(s, _)| s <= va);
        covered[..i]
            .iter()
            .rev()
            .take(64)
            .any(|&(s, e)| s <= va && va < e)
    };
    let fdes = fde_ranges(store);
    let align = arch.insn_alignment().max(1);
    let candidate = |t: Va| {
        t.0.is_multiple_of(align)
            && !entries.contains_key(&t)
            && image.at(t).is_some()
            && !inside(t)
            // Inside a split-off part, or strictly inside any FDE's range: an
            // FDE gives a function's real extent, so an address taken in its
            // middle is a label (a computed jump in hand-written assembly), not
            // a function. An FDE's own start was already promoted.
            && !fdes
                .iter()
                .any(|&(s, e, _, mid, _)| (mid && s <= t && t < e) || (s < t && t < e))
    };
    let mut found: BTreeMap<Va, Vec<PtrSource<'_>>> = BTreeMap::new();
    for r in bin.relocations.iter().filter(|r| r.applied_at_load) {
        let target = match r.kind {
            fg_loader::RelocKind::Relative | fg_loader::RelocKind::IndirectRelative => r
                .addend
                .map(|a| a as u64)
                .or_else(|| r.stored_value.as_ref().map(|v| v.value)),
            _ => None,
        };
        if let Some(t) = target.map(Va).filter(|&t| candidate(t)) {
            found.entry(t).or_default().push(PtrSource::Reloc(r));
        }
    }
    // A file loaded at a fixed address keeps its pointers without relocations:
    // every aligned word of data that holds the address of clean code is one.
    if data_words && image.fixed {
        let word = if matches!(bin.bitness, fg_core::Bitness::Bits64) {
            8
        } else {
            4
        };
        for &(start, len, bytes) in &image.data {
            let first = (start.next_multiple_of(word) - start) as usize;
            for (i, w) in bytes[first.min(bytes.len())..]
                .chunks_exact(word as usize)
                .enumerate()
            {
                let v = w.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x));
                let at = start + first as u64 + i as u64 * word;
                // A word a relocation writes (a GOT entry holding the PLT's
                // lazy-binding address until the import is bound) is not a
                // pointer the program keeps.
                if at + word <= start + len
                    && !image.reloc_sites.contains(&at)
                    && v >= MIN_ABSOLUTE
                    && candidate(Va(v))
                    && image.starts_cleanly(arch, Va(v))
                {
                    found
                        .entry(Va(v))
                        .or_default()
                        .push(PtrSource::Data(Va(at)));
                }
            }
        }
    }
    for (&fentry, f) in &cfg.functions {
        for &(site, t) in &f.addr_refs {
            if candidate(t) {
                found
                    .entry(t)
                    .or_default()
                    .push(PtrSource::Code(site, fentry));
            }
        }
    }
    let w = Confidence::new(0.8).unwrap_or(Confidence::ZERO);
    found
        .into_iter()
        .filter_map(|(target, sources)| {
            let mut inputs = Vec::new();
            let ev = sources
                .iter()
                .take(MAX_CALLERS)
                .map(|src| match *src {
                    PtrSource::Reloc(r) => {
                        let place = r.va.map_or(String::new(), |v| format!(" at {v}"));
                        Support::new(
                            EvidenceKind::Format,
                            Evidence::at(
                                format!(
                                    "the loader stores this address{place} ({})",
                                    r.kind.meaning()
                                ),
                                r.defined_by,
                            ),
                            w,
                        )
                        .at(r.va.unwrap_or(target))
                    }
                    PtrSource::Data(at) => Support::new(
                        EvidenceKind::Pattern,
                        Evidence::new(format!(
                            "stored at {at}, in data of a file loaded at a fixed address"
                        )),
                        w,
                    )
                    .at(at),
                    PtrSource::Code(site, fentry) => {
                        let id = entries[&fentry].0;
                        if !inputs.contains(&id) {
                            inputs.push(id);
                        }
                        Support::new(
                            EvidenceKind::Flow,
                            Evidence::new(format!(
                                "address taken at {site} in the function at {fentry}"
                            )),
                            w,
                        )
                        .at(site)
                    }
                })
                .collect();
            let mut prov = Provenance::new(PASS_POINTERS, VERSION);
            prov.inputs = inputs;
            prov.insns = vec![target];
            Fact::new(
                Claim::IsFunction { entry: target },
                Status::Inferred,
                w,
                prov,
                ev,
            )
            .ok()
        })
        .collect()
}

/// Jumps that leave their function into code no FDE covers: out of the
/// caller's own entry-state FDE, or, when the caller has no FDE, the jump of a
/// thunk (a function that is only that jump). Their targets become functions
/// (tail calls). Without unwind information a backward jump proves nothing:
/// gcc places split-off parts before their function.
fn tail_call_facts(
    image: &Image<'_>,
    arch: &dyn Arch,
    cfg: &Cfg,
    entries: &BTreeMap<Va, (FactId, u32)>,
    store: &FactStore,
) -> Vec<Fact> {
    let fdes = fde_ranges(store);
    let covering = |va: Va| fdes.iter().find(|(s, e, ..)| *s <= va && va < *e);
    let mut found: BTreeMap<Va, (Va, Va, bool)> = BTreeMap::new();
    for (&fentry, f) in &cfg.functions {
        let own = covering(fentry)
            .filter(|&&(_, _, _, mid, _)| !mid)
            .map(|&(s, e, ..)| (s, e));
        for (&bstart, b) in &f.blocks {
            for &(t, k) in &b.succs {
                if !matches!(k, EdgeKind::Jump | EdgeKind::CondTaken)
                    || entries.contains_key(&t)
                    || image.at(t).is_none()
                {
                    continue;
                }
                // Code an FDE covers is explained by its FDE: an entry-state one
                // was promoted, a mid-frame one is a split-off part. Hand-written
                // assembly often has FDEs covering only part of a function, so a
                // jump between them is not a tail call.
                if covering(t).is_some() {
                    continue;
                }
                let thunk = match own {
                    Some((s, e)) if t < s || t >= e => false,
                    // A function that is only a jump (after at most a landing
                    // pad such as `endbr64` or `bti`) is a thunk to a function.
                    // Only the entry block's jump: the target's code may already
                    // have been decoded as part of the thunk.
                    None if bstart == fentry
                        && k == EdgeKind::Jump
                        && is_thunk(image, arch, f, fentry, t) =>
                    {
                        true
                    }
                    _ => continue,
                };
                found.entry(t).or_insert((b.last, fentry, thunk));
            }
        }
    }
    found
        .into_iter()
        .filter_map(|(target, (site, fentry, thunk))| {
            let (id, _) = entries[&fentry];
            let caller = store.get(id)?.confidence();
            let w = Confidence::new(0.8)?;
            let why = if thunk {
                "the caller is only this jump"
            } else {
                "outside the caller's unwind range"
            };
            let ev = Support::new(
                EvidenceKind::Flow,
                Evidence::new(format!(
                    "jump from {site} in the function at {fentry} leaves it ({why})"
                )),
                w,
            )
            .at(site);
            let mut prov = Provenance::new(PASS_TAILCALLS, VERSION);
            prov.inputs = vec![id];
            prov.insns = vec![site];
            Fact::new(
                Claim::IsFunction { entry: target },
                Status::Inferred,
                Confidence::derived([caller], w),
                prov,
                vec![ev],
            )
            .ok()
        })
        .collect()
}

/// The function's entry block is only a jump out of the function: at most two
/// instructions ending in a jump (a landing pad such as `endbr64` or `bti`,
/// then `jmp`), or at most four (argument set-up, then a tail call) ending in a
/// jump either back to before the entry, or forward over nothing but padding
/// to the next code. A jump inside a function from its entry block, such as
/// the one to a rotated loop's condition, goes forward over the function's own
/// blocks (the loop body).
fn is_thunk(image: &Image<'_>, arch: &dyn Arch, f: &Function, entry: Va, target: Va) -> bool {
    let Some(b) = f.blocks.get(&entry) else {
        return false;
    };
    if !matches!(b.succs.as_slice(), [(_, EdgeKind::Jump)]) {
        return false;
    }
    if b.insns <= 2 || (b.insns <= 4 && target < entry) {
        return true;
    }
    b.insns <= 4
        && target >= b.end
        && f.blocks.range(..target).count() == 1
        && only_padding(image, arch, b.end, target)
}

/// Every instruction in `[from, to)` is a no-op, ending exactly at `to`.
fn only_padding(image: &Image<'_>, arch: &dyn Arch, from: Va, to: Va) -> bool {
    let mut va = from;
    while va < to {
        let Some(insn) = image
            .at(va)
            .and_then(|b| arch.decode(b, va, Mode::Native).ok())
        else {
            return false;
        };
        if !insn.nop {
            return false;
        }
        va = Va(va.0 + insn.len());
    }
    va == to
}

/// FDE ranges that are parts of another function rather than functions.
fn fragments(cfg: &Cfg, store: &FactStore) -> BTreeMap<Va, Va> {
    let reached = reached_blocks(cfg);
    fde_ranges(store)
        .into_iter()
        .filter(|(s, ..)| !cfg.functions.contains_key(s))
        .filter_map(|(s, ..)| reached.get(&s).map(|&owner| (s, owner)))
        .collect()
}
