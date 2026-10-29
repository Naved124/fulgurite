//! Function-start recall and precision on a binary with symbols, analysed as
//! `strip` would leave it (no static symbol table): `cargo run -p fg-analysis --example recall -- FILE...`.
//! Ground truth: defined function symbols in executable memory, except
//! compiler-split `.cold` parts.
//!
//! Environment: `VERBOSE=1` lists misses and extras with their evidence,
//! `NORETURN=1` the functions found not to return, `UNRESOLVED=1` the
//! indirect jumps not resolved, `STALE=1` functions found
//! only as call targets whose calls are no longer decoded (they followed a
//! call later proven not to return), `DUMP=ADDR` one function's blocks.

use fg_analysis::{cfg, seeds};
use fg_facts::FactStore;
use fg_ir::{Arch, Mode};
use fg_loader::{LoadOptions, SymbolKind};
use std::collections::BTreeSet;

fn main() {
    let verbose = std::env::var_os("VERBOSE").is_some();
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path).expect("read");
        let mut bin = fg_loader::load(&bytes, &LoadOptions::default()).expect("load");
        let exec = |va: u64| {
            bin.segments
                .iter()
                .any(|s| s.perms.execute && va >= s.va.0 && va - s.va.0 < s.mem_size)
        };
        let truth: BTreeSet<u64> = bin
            .symbols
            .iter()
            .filter(|s| s.defined && s.kind == SymbolKind::Function && exec(s.va.0))
            // Compiler-split parts are function chunks, not functions.
            .filter(|s| !s.name.contains(".cold"))
            .map(|s| s.va.0)
            .collect();
        let names: std::collections::BTreeMap<u64, String> = bin
            .symbols
            .iter()
            .map(|s| (s.va.0, s.name.clone()))
            .collect();
        // What `strip` removes: the static symbol table. Exports stay, since a
        // shared library cannot work without them.
        bin.symbols
            .retain(|s| s.table != fg_loader::SymbolTable::Static);
        let (arch, mode): (&dyn Arch, Mode) = match bin.arch {
            fg_core::ArchId::Aarch64 => (&fg_arch_arm64::ARM64, Mode::Native),
            id => (
                fg_arch_x86::X86::for_arch(id).expect("x86"),
                if bin.bitness == fg_core::Bitness::Bits64 {
                    Mode::X86_64
                } else {
                    Mode::X86_32
                },
            ),
        };
        let mut store = FactStore::new();
        seeds::add_seed_facts(&bin, &mut store).expect("seeds");
        let t = std::time::Instant::now();
        let g = cfg::recover(&bin, &bytes, arch, mode, &mut store).expect("cfg");
        let found: BTreeSet<u64> = g.functions.keys().map(|v| v.0).collect();
        let hit = truth.intersection(&found).count();
        let plt: Vec<(u64, u64)> = bin
            .sections
            .iter()
            .filter(|s| s.name.starts_with(".plt"))
            .filter_map(|s| s.va.map(|v| (v.0, v.0 + s.size)))
            .collect();
        let extra: Vec<u64> = found
            .difference(&truth)
            .copied()
            .filter(|v| !plt.iter().any(|&(a, b)| *v >= a && *v < b))
            .collect();
        let unresolved: std::collections::BTreeSet<_> = g
            .functions
            .values()
            .flat_map(|f| f.blocks.values())
            .filter(|b| b.unresolved)
            .map(|b| b.last)
            .collect();
        println!(
            "{path}: truth {} found {} recall {:.2}% precision {:.2}% (PLT stubs excluded) rounds {} fragments {} no-return {} jump tables {} unresolved jumps {} in {:?}",
            truth.len(),
            found.len(),
            100.0 * hit as f64 / truth.len().max(1) as f64,
            100.0 * hit as f64 / (hit + extra.len()).max(1) as f64,
            g.rounds,
            g.fragments.len(),
            g.no_return.len(),
            g.tables.len(),
            unresolved.len(),
            t.elapsed()
        );
        if std::env::var_os("UNRESOLVED").is_some() {
            for (e, f) in &g.functions {
                for b in f.blocks.values().filter(|b| b.unresolved) {
                    println!(
                        "  unresolved {} in {e} {}",
                        b.last,
                        names.get(&e.0).map_or("", |s| s)
                    );
                }
            }
        }
        if let Some(d) = std::env::var_os("DUMP") {
            let a = u64::from_str_radix(d.to_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            if let Some(f) = g.functions.get(&fg_core::Va(a)) {
                for (s, b) in &f.blocks {
                    println!(
                        "  {s}..{} last {} succs {:?} nrc {} imp {:?} unres {} bad {}",
                        b.end,
                        b.last,
                        b.succs,
                        b.no_return_call,
                        b.import,
                        b.unresolved,
                        b.bad_decode
                    );
                }
            }
        }
        if std::env::var_os("STALE").is_some() {
            let called: BTreeSet<u64> = g
                .functions
                .values()
                .flat_map(|f| f.calls.iter().map(|c| c.1.0))
                .collect();
            for e in g.functions.keys() {
                if let fg_facts::Verdict::Accepted(id) = store
                    .resolve(&fg_facts::Slot::IsFunction { entry: *e })
                    .verdict
                {
                    let f = store.get(id).unwrap();
                    if f.provenance().pass == "cfg.calls" && !called.contains(&e.0) {
                        println!("  STALE {e} {}", names.get(&e.0).map_or("", |s| s));
                    }
                }
            }
        }
        if std::env::var_os("NORETURN").is_some() {
            for e in &g.no_return {
                println!("  no-return {e} {}", names.get(&e.0).map_or("", |s| s));
            }
        }
        if verbose {
            for m in truth.difference(&found) {
                println!("  missed {m:#x} {}", names.get(m).map_or("", |s| s));
            }
            for e in &extra {
                println!("  extra  {e:#x} {}", names.get(e).map_or("", |s| s));
                for f in store.facts_in(&fg_facts::Slot::IsFunction {
                    entry: fg_core::Va(*e),
                }) {
                    for ev in f.evidence() {
                        println!("         {}: {}", f.provenance().pass, ev.evidence.text);
                    }
                }
            }
        }
    }
}
