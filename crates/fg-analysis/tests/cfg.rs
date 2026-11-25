// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Function-start recovery on stripped binaries, scored against the symbols
//! the stripping removed: the test program itself, and a C program built here
//! with gcc and clang at -O2, with and without unwind tables.

use fg_analysis::{cfg, seeds};
use fg_core::Va;
use fg_facts::{FactStore, Slot, Verdict};
use fg_ir::{Arch, Mode};
use fg_loader::{LoadOptions, LoadedBinary, SymbolKind, SymbolTable};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every way code is reached that recovery must handle without symbols.
const PROGRAM: &str = include_str!("data/program.c");

struct Score {
    truth: usize,
    hit: usize,
    extra: Vec<u64>,
    missed: Vec<u64>,
    missed_names: Vec<String>,
    /// Names of the functions found not to return (PLT stubs left out).
    no_return: BTreeSet<String>,
    /// Names of the functions with an indirect jump not resolved.
    unresolved: BTreeSet<String>,
    /// Targets of each resolved indirect jump, by the name of its function.
    tables: Vec<(String, usize)>,
}

/// Recovers functions from `bytes` with the static symbol table removed (what
/// `strip` does) and scores them against it. Compiler-split `.cold` parts are
/// function chunks, not functions; PLT stubs are not scored.
fn score(bytes: &[u8]) -> Score {
    let mut bin = fg_loader::load(bytes, &LoadOptions::default()).unwrap();
    let exec = |b: &LoadedBinary, va: u64| {
        b.segments
            .iter()
            .any(|s| s.perms.execute && va >= s.va.0 && va - s.va.0 < s.mem_size)
    };
    let truth: BTreeSet<u64> = bin
        .symbols
        .iter()
        .filter(|s| s.defined && s.kind == SymbolKind::Function && exec(&bin, s.va.0))
        .filter(|s| !s.name.contains(".cold"))
        .map(|s| s.va.0)
        .collect();
    let names: std::collections::BTreeMap<u64, String> = bin
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Function)
        .map(|s| (s.va.0, s.name.clone()))
        .collect();
    bin.symbols.retain(|s| s.table != SymbolTable::Static);

    let (arch, mode): (&dyn Arch, Mode) = match bin.arch {
        fg_core::ArchId::Aarch64 => (&fg_arch_arm64::ARM64, Mode::Native),
        id => (
            fg_arch_x86::X86::for_arch(id).unwrap(),
            if bin.bitness == fg_core::Bitness::Bits64 {
                Mode::X86_64
            } else {
                Mode::X86_32
            },
        ),
    };
    let mut store = FactStore::new();
    seeds::add_seed_facts(&bin, &mut store).unwrap();
    let g = cfg::recover(&bin, bytes, arch, mode, &mut store).unwrap();

    // No function's blocks run into another function's entry: decoding stops at
    // calls that never return instead of running on into the next function.
    for (e, f) in &g.functions {
        for (s, b) in &f.blocks {
            if let Some((other, _)) = g
                .functions
                .range(*s..b.end)
                .find(|(o, _)| *o != e && *o != s)
            {
                panic!(
                    "the function at {e} has a block {s}..{} over the entry {other}",
                    b.end
                );
            }
        }
    }
    // Every recovered function is an accepted fact whose evidence says why.
    for &e in g.functions.keys() {
        let Verdict::Accepted(id) = store.resolve(&Slot::IsFunction { entry: e }).verdict else {
            panic!("{e} is not an accepted function");
        };
        assert!(!store.get(id).unwrap().evidence().is_empty());
    }
    // Through the cache and back: the same facts, and re-running every pass on
    // the reloaded store changes nothing.
    let mut cache = fg_store::Cache::in_memory().unwrap();
    cache.save("bin", &store).unwrap();
    let mut store = cache.load("bin").unwrap().unwrap();
    assert_eq!(seeds::add_seed_facts(&bin, &mut store).unwrap(), 0);
    // Running recovery again finds the same functions and adds nothing.
    let n = store.len();
    let again = cfg::recover(&bin, bytes, arch, mode, &mut store).unwrap();
    assert_eq!(store.len(), n);
    assert_eq!(
        again.functions.keys().collect::<Vec<_>>(),
        g.functions.keys().collect::<Vec<_>>()
    );

    let plt: Vec<(u64, u64)> = bin
        .sections
        .iter()
        .filter(|s| s.name.starts_with(".plt"))
        .filter_map(|s| s.va.map(|v| (v.0, v.0 + s.size)))
        .collect();
    let found: BTreeSet<u64> = g.functions.keys().map(|v| v.0).collect();
    let in_plt = |v: u64| plt.iter().any(|&(a, b)| v >= a && v < b);
    let name = |v: Va| {
        let n = names.get(&v.0).cloned().unwrap_or_else(|| v.to_string());
        n.split('.').next().unwrap_or(&n).to_string()
    };
    let unresolved = g
        .functions
        .iter()
        .filter(|(_, f)| f.blocks.values().any(|b| b.unresolved))
        .map(|(&e, _)| name(e))
        .collect();
    let mut tables = Vec::new();
    for (&e, f) in &g.functions {
        for b in f.blocks.values() {
            if let Some(t) = g.tables.get(&b.last) {
                tables.push((name(e), t.len()));
            }
        }
    }
    let no_return = g
        .no_return
        .iter()
        .filter(|v| !in_plt(v.0))
        .map(|v| {
            let n = names.get(&v.0).cloned().unwrap_or_else(|| v.to_string());
            // A compiler's clone (`die.constprop.0`) is the function.
            n.split('.').next().unwrap_or(&n).to_string()
        })
        .collect();
    Score {
        truth: truth.len(),
        hit: truth.intersection(&found).count(),
        extra: found
            .difference(&truth)
            .copied()
            .filter(|&v| !in_plt(v))
            .collect(),
        missed: truth.difference(&found).copied().collect(),
        missed_names: truth
            .difference(&found)
            .map(|v| names.get(v).cloned().unwrap_or_default())
            .collect(),
        no_return,
        unresolved,
        tables,
    }
}

#[test]
fn the_test_program_itself() {
    let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    if fg_loader::detect(&bytes) != Some(fg_loader::Format::Elf) {
        eprintln!("note: not an ELF test binary; skipped");
        return;
    }
    let s = score(&bytes);
    eprintln!(
        "self: {} functions, {} found, {} extra",
        s.truth,
        s.hit,
        s.extra.len()
    );
    assert!(s.truth > 500);
    assert!(s.missed.is_empty(), "missed {:x?}", s.missed);
    assert!(s.extra.is_empty(), "extra {:x?}", s.extra);
}

fn out_dir() -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg-corpus");
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn c_at_o2_with_and_without_unwind_tables() {
    let dir = out_dir();
    let src = dir.join("program.c");
    std::fs::write(&src, PROGRAM).unwrap();
    let mut built = 0;
    for cc in ["gcc", "clang"] {
        // Retpolines (x86 only; elsewhere the build fails and is skipped):
        // every indirect call goes through a thunk that calls a label inside
        // itself, with a capture loop after the call.
        let retpoline: &[&str] = match cc {
            "gcc" => &["-mindirect-branch=thunk", "-fcf-protection=none"],
            _ => &["-mretpoline", "-fcf-protection=none"],
        };
        for (tag, flags) in [
            ("uw", &[][..]),
            (
                "nouw",
                &["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"][..],
            ),
            ("retpoline", retpoline),
        ] {
            for (kind, link) in [
                ("pie", &["-pie", "-fPIE"][..]),
                ("so", &["-shared", "-fPIC"][..]),
                // Absolute jump tables (`jmp [8*rax + table]`).
                ("exe", &["-no-pie", "-fno-pie"][..]),
            ] {
                let out = dir.join(format!("{cc}-{tag}-{kind}"));
                let st = Command::new(cc)
                    // `-fcf-protection` (an `endbr64` at every function) is
                    // the default on several distributions.
                    .args(["-O2", "-fcf-protection=full", "-o"])
                    .arg(&out)
                    .args(flags)
                    .args(link)
                    .arg(&src)
                    .status();
                if !matches!(st, Ok(s) if s.success()) {
                    eprintln!("note: {cc} unavailable or failed; skipped");
                    continue;
                }
                built += 1;
                let s = score(&std::fs::read(&out).unwrap());
                eprintln!(
                    "{cc}-{tag}-{kind}: {} functions, {} found, extra {:x?}, missed {:x?}",
                    s.truth, s.hit, s.extra, s.missed
                );
                // With retpolines clang compiles the call through `table` to
                // compares and still emits its thunk, which then nothing
                // references and no FDE covers.
                let allowed: &[&str] = match (cc, tag, kind) {
                    ("clang", "retpoline", _) => &["__llvm_retpoline_r11"],
                    _ => &[],
                };
                assert!(
                    s.missed_names.iter().all(|n| allowed.contains(&n.as_str())),
                    "{cc}-{tag}-{kind}: missed {:?} at {:x?}",
                    s.missed_names,
                    s.missed
                );
                assert!(
                    s.extra.is_empty(),
                    "{cc}-{tag}-{kind}: extra {:x?}",
                    s.extra
                );
                // Exactly the functions that never return, and no others: a
                // wrong one would hide the code after every call to it.
                // `_start` ends in a call to `__libc_start_main` and `hlt`.
                let mut expect: BTreeSet<String> =
                    ["die", "give_up", "spin"].map(String::from).into();
                if kind != "so" {
                    expect.insert("_start".into());
                }
                assert_eq!(
                    s.no_return, expect,
                    "{cc}-{tag}-{kind}: no-return functions"
                );
                // The switch's jump table is read: eight cases, each its own
                // code (retpolines turn it into compares).
                eprintln!("  tables {:?}, unresolved {:?}", s.tables, s.unresolved);
                // Every indirect jump is resolved but crt's, which jump through
                // a pointer read at run time.
                assert!(
                    s.unresolved
                        .iter()
                        .all(|n| n.ends_with("register_tm_clones")),
                    "{cc}-{tag}-{kind}: unresolved in {:?}",
                    s.unresolved
                );
                if tag != "retpoline" {
                    assert!(
                        s.tables.iter().any(|(n, k)| n == "classify" && *k >= 8),
                        "{cc}-{tag}-{kind}: {:?}",
                        s.tables
                    );
                }
            }
        }
    }
    if built == 0 {
        eprintln!("note: no C compiler; skipped");
    }
}

/// A freestanding AArch64 program (no C library for the target is needed):
/// a jump table, function pointers, and calls through the PLT into a shared
/// library, one of them to `abort`.
const AARCH64_PROGRAM: &str = include_str!("data/aarch64.c");

const AARCH64_LIBRARY: &str = include_str!("data/aarch64-dep.c");

/// `rust-lld`, the linker that ships with Rust, if it is installed.
fn rust_lld() -> Option<PathBuf> {
    let out = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()?;
    let sysroot = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    std::fs::read_dir(sysroot.join("lib/rustlib"))
        .ok()?
        .flatten()
        .map(|d| d.path().join("bin/rust-lld"))
        .find(|p| p.exists())
}

#[test]
fn aarch64_tables_address_pairs_and_plt() {
    let Some(lld) = rust_lld() else {
        eprintln!("note: rust-lld not found; skipped");
        return;
    };
    let dir = out_dir().join("aarch64");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, text: &str| {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let (prog, lib) = (
        write("prog.c", AARCH64_PROGRAM),
        write("dep.c", AARCH64_LIBRARY),
    );
    let run = |cmd: &mut Command| matches!(cmd.status(), Ok(s) if s.success());
    let cc = |src: &Path, obj: &Path, flags: &[&str]| {
        run(Command::new("clang")
            .args([
                "--target=aarch64-linux-gnu",
                "-O2",
                "-ffreestanding",
                "-fno-builtin",
            ])
            .args(["-nostdlib", "-mbranch-protection=standard", "-c", "-o"])
            .arg(obj)
            .args(flags)
            .arg(src))
    };
    let dep_o = dir.join("dep.o");
    let libdep = dir.join("libdep.so");
    if !cc(&lib, &dep_o, &["-fPIC"])
        || !run(Command::new(&lld)
            .args(["-flavor", "gnu", "-shared", "-soname", "libdep.so", "-o"])
            .arg(&libdep)
            .arg(&dep_o))
    {
        eprintln!("note: clang cannot build for AArch64; skipped");
        return;
    }
    for (tag, unwind) in [
        // Freestanding code gets no unwind tables unless asked.
        ("uw", &["-fasynchronous-unwind-tables"][..]),
        (
            "nouw",
            &["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"][..],
        ),
    ] {
        for (kind, cflags, lflags) in [
            ("pie", &["-fPIE"][..], &["-pie"][..]),
            ("exe", &["-fno-pic"][..], &["-no-pie"][..]),
        ] {
            let obj = dir.join(format!("prog-{tag}-{kind}.o"));
            let out = dir.join(format!("prog-{tag}-{kind}"));
            let flags: Vec<&str> = cflags.iter().chain(unwind).copied().collect();
            assert!(cc(&prog, &obj, &flags), "{tag}-{kind}: compile");
            assert!(
                run(Command::new(&lld)
                    .args(["-flavor", "gnu", "-e", "_start", "-z", "now"])
                    .args(lflags)
                    .arg("-o")
                    .arg(&out)
                    .arg(&obj)
                    .arg(&libdep)),
                "{tag}-{kind}: link"
            );
            let s = score(&std::fs::read(&out).unwrap());
            eprintln!(
                "aarch64-{tag}-{kind}: {} functions, {} found, extra {:x?}, missed {:?}\n  tables {:?}, unresolved {:?}, no-return {:?}",
                s.truth, s.hit, s.extra, s.missed_names, s.tables, s.unresolved, s.no_return
            );
            assert!(
                s.missed.is_empty(),
                "aarch64-{tag}-{kind}: missed {:?}",
                s.missed_names
            );
            assert!(
                s.extra.is_empty(),
                "aarch64-{tag}-{kind}: extra {:x?}",
                s.extra
            );
            // The PLT stubs' `br x17` goes through the import's slot; the
            // switch's table is read.
            assert!(
                s.unresolved.is_empty(),
                "aarch64-{tag}-{kind}: {:?}",
                s.unresolved
            );
            assert!(
                s.tables.iter().any(|(n, k)| n == "classify" && *k >= 7),
                "aarch64-{tag}-{kind}: {:?}",
                s.tables
            );
            // `die` calls `abort` through the PLT. `_start` calls `classify`,
            // which starts right after it: without unwind tables nothing but
            // that call says `classify` is a function, and a call to the code
            // right after a function's own may be a stack trick, so `_start`
            // may return.
            let mut expect: BTreeSet<String> = ["die"].map(String::from).into();
            if tag == "uw" {
                expect.insert("_start".into());
            }
            assert_eq!(s.no_return, expect, "aarch64-{tag}-{kind}");
        }
    }
}

/// Found by fuzzing (2026-10-21): a branch to bytes that do not decode makes a
/// block with no instructions (it ends where it starts). The check for blocks
/// running over a function that only an FDE declares asked for the entries
/// strictly inside each block, a range that is empty and invalid for such a
/// block, and panicked.
#[test]
fn a_branch_to_undecodable_bytes_beside_an_fde_only_function() {
    let dir = out_dir();
    let src = dir.join("bad-branch.s");
    std::fs::write(
        &src,
        "\t.text\n\t.globl _start\n_start:\n\t.cfi_startproc\n\ttest %edi, %edi\n\tje 1f\n\
         \tret\n1:\t.byte 0x06\n\t.cfi_endproc\n\
         alone:\n\t.cfi_startproc\n\tmov $60, %eax\n\tsyscall\n\tret\n\t.cfi_endproc\n",
    )
    .unwrap();
    let out = dir.join("bad-branch");
    let st = Command::new("gcc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&out)
        .arg(&src)
        .status();
    if !matches!(st, Ok(s) if s.success()) {
        eprintln!("note: gcc unavailable or failed; skipped");
        return;
    }
    let s = score(&std::fs::read(&out).unwrap());
    assert!(s.missed.is_empty(), "missed {:x?}", s.missed);
}
