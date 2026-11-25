// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! The seed pass: what the file itself declares about code, as facts
//! (design §8.2).
//!
//! | Source | Facts | Weight |
//! |---|---|---|
//! | Entry point | `IsFunction` | 1.0 |
//! | Defined function symbols, function-like PE exports | `IsFunction`, `IsCode` (with a size), `Name` | 0.98 |
//! | PE exception table (`.pdata`) | `IsFunction`, `IsCode` | 0.97 |
//! | `.eh_frame` FDEs, PE exception-table fragments | `IsCode` only | 0.97 |
//! | `DT_INIT`/`DT_FINI`, `.init`/`.fini` sections, init/fini arrays, TLS callbacks, CFG targets, SafeSEH handlers | `IsFunction` | 0.95 |
//!
//! An FDE describes a code range, not always a function: the linker gives whole
//! PLT sections one, hand-written assembly can start one in alignment padding,
//! glibc's `__restore_rt` starts one a byte early, and compilers give split-off
//! `.cold` parts their own. So FDEs only say "this is code" here; CFG recovery,
//! which can decode, decides which ones are function entries.
//!
//! When several sources make the same claim they become one fact whose evidence
//! lists all of them, with the weights combined by noisy-OR.

use fg_core::{Evidence, Va};
use fg_facts::{
    Claim, Confidence, EvidenceKind, Fact, FactError, FactStore, Provenance, Status, StoreError,
    Support,
};
use fg_loader::{LoadedBinary, Seed, SeedKind, Symbol, SymbolBinding, SymbolKind, SymbolTable};
use std::collections::BTreeMap;

/// The pass name in every fact's provenance.
pub const PASS: &str = "seeds";
/// Bumped when the pass's output for the same file changes.
pub const VERSION: u32 = 1;

fn w(v: f32) -> Confidence {
    Confidence::new(v).unwrap_or(Confidence::ZERO)
}

/// The facts the file declares, in claim order.
pub fn seed_facts(bin: &LoadedBinary) -> Result<Vec<Fact>, FactError> {
    let mut by_claim: BTreeMap<Claim, Vec<Support>> = BTreeMap::new();
    let mut add = |claim: Claim, s: Support| by_claim.entry(claim).or_default().push(s);

    for seed in &bin.seeds {
        let s = seed_support(seed);
        let func = Claim::IsFunction { entry: seed.va };
        match seed.kind {
            SeedKind::UnwindTable
            | SeedKind::UnwindFragment
            | SeedKind::UnwindSignal
            | SeedKind::ExceptionFragment => {}
            _ => add(func, s.clone()),
        }
        if let Some(end) = seed.end.filter(|e| *e > seed.va) {
            add(
                Claim::IsCode {
                    start: seed.va,
                    end,
                },
                s,
            );
        }
    }

    // `_init` and `_fini` live in sections of their own; in a static binary
    // nothing else declares them (no dynamic section, no FDE).
    for sec in &bin.sections {
        let Some(va) = sec.va.filter(|_| sec.perms.execute && sec.size > 0) else {
            continue;
        };
        let what = match sec.name.as_str() {
            ".init" => "section .init: the initialisation function",
            ".fini" => "section .fini: the termination function",
            _ => continue,
        };
        add(
            Claim::IsFunction { entry: va },
            Support::new(
                EvidenceKind::Format,
                Evidence::at(what, sec.defined_by),
                w(0.95),
            )
            .at(va),
        );
    }

    let mut names: BTreeMap<Va, Vec<&Symbol>> = BTreeMap::new();
    for sym in bin.symbols.iter().filter(|s| is_function_symbol(bin, s)) {
        let s = symbol_support(sym);
        add(Claim::IsFunction { entry: sym.va }, s.clone());
        if let Some(end) = sym.va.checked_add(sym.size).filter(|_| sym.size > 0) {
            add(Claim::IsCode { start: sym.va, end }, s);
        }
        // An IFUNC symbol's address is its resolver, which is not the function
        // the name stands for; it is not named after it. Names a fact cannot
        // hold (control characters, from a hostile file) are left out.
        let name = sym.display_name();
        if sym.kind != SymbolKind::IndirectFunction
            && !name.is_empty()
            && !name.chars().any(char::is_control)
        {
            names.entry(sym.va).or_default().push(sym);
        }
    }
    for (va, mut syms) in names {
        syms.sort_by_key(|s| name_rank(s));
        syms.dedup_by(|a, b| a.display_name() == b.display_name());
        let primary = syms[0].display_name();
        for s in syms {
            let mut sup = symbol_support(s);
            if s.display_name() != primary {
                sup.evidence.text = format!("also named {}", sup.evidence.text);
            }
            let claim = Claim::Name {
                entity: va,
                name: primary.clone(),
            };
            add(claim, sup);
        }
    }

    by_claim
        .into_iter()
        .map(|(claim, evidence)| {
            let conf = Confidence::any_of(evidence.iter().map(|s| s.weight));
            Fact::new(
                claim,
                Status::Declared,
                conf,
                Provenance::new(PASS, VERSION),
                evidence,
            )
        })
        .collect()
}

/// Runs the pass into a store. Returns how many facts were added or changed.
pub fn add_seed_facts(bin: &LoadedBinary, store: &mut FactStore) -> Result<usize, SeedError> {
    let mut changed = 0;
    for f in seed_facts(bin).map_err(SeedError::Fact)? {
        if store.insert(f).map_err(SeedError::Store)? != fg_facts::Inserted::Unchanged {
            changed += 1;
        }
    }
    Ok(changed)
}

/// Why the pass failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SeedError {
    /// A fact could not be built (a bug in the pass: the loader's values are checked).
    Fact(FactError),
    /// The store refused a fact.
    Store(StoreError),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::Fact(e) => write!(f, "seed fact: {e}"),
            SeedError::Store(e) => write!(f, "seed fact: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

fn seed_support(seed: &Seed) -> Support {
    let (kind, weight) = match seed.kind {
        SeedKind::Entry => (EvidenceKind::Format, 1.0),
        SeedKind::ExceptionTable
        | SeedKind::ExceptionFragment
        | SeedKind::UnwindTable
        | SeedKind::UnwindFragment
        | SeedKind::UnwindSignal => (EvidenceKind::Format, 0.97),
        _ => (EvidenceKind::Format, 0.95),
    };
    Support::new(
        kind,
        Evidence::at(seed.kind.meaning(), seed.defined_by),
        w(weight),
    )
    .at(seed.va)
}

fn symbol_support(sym: &Symbol) -> Support {
    let table = match sym.table {
        SymbolTable::Dynamic => "dynamic symbol",
        SymbolTable::Static => "symbol",
        SymbolTable::Exports => "export",
        SymbolTable::Coff => "COFF symbol",
        _ => "symbol",
    };
    Support::new(
        EvidenceKind::Symbol,
        Evidence::at(format!("{table} {}", sym.display_name()), sym.defined_by),
        w(0.98),
    )
    .at(sym.va)
}

/// A defined symbol naming code in this file. PE exports carry no type, so an
/// export counts when it lands in executable memory and is not forwarded.
fn is_function_symbol(bin: &LoadedBinary, s: &Symbol) -> bool {
    if !s.defined || s.va.0 == 0 {
        return false;
    }
    match s.kind {
        SymbolKind::Function | SymbolKind::IndirectFunction => true,
        _ => {
            s.table == SymbolTable::Exports
                && s.forwarder.is_none()
                && bin
                    .segments
                    .iter()
                    .any(|g| g.perms.execute && s.va.0 >= g.va.0 && s.va.0 - g.va.0 < g.mem_size)
        }
    }
}

/// Which alias names a function: exported or global names before weak and
/// local ones, then fewer leading underscores (`malloc` over `__libc_malloc`),
/// then the shorter name, then alphabetical, so the choice never depends on
/// table order.
fn name_rank(s: &Symbol) -> (u8, usize, usize, String) {
    let n = s.display_name();
    let binding = match (s.table, s.binding) {
        (SymbolTable::Exports, _) | (SymbolTable::Dynamic, SymbolBinding::Global) => 0,
        (_, SymbolBinding::Global) => 1,
        (_, SymbolBinding::Weak) => 2,
        _ => 3,
    };
    let underscores = n.bytes().take_while(|&b| b == b'_').count();
    (binding, underscores, n.len(), n)
}
