//! Cross-references checked against the linker's own record of them: built
//! with `--emit-relocs`, a program keeps its code relocations (`.rela.text`),
//! and each one says which instruction refers to which address.

#![allow(missing_docs)]

use fg_analysis::xrefs::{self, Via, XrefKind};
use fg_analysis::{cfg, seeds};
use fg_core::Va;
use fg_facts::FactStore;
use fg_ir::{Arch, Mode};
use fg_loader::{LoadOptions, LoadedBinary, SymbolBinding};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const PROGRAM: &str = include_str!("data/program.c");
const AARCH64_PROGRAM: &str = include_str!("data/aarch64.c");
const AARCH64_LIBRARY: &str = include_str!("data/aarch64-dep.c");
const PIC32: &str = include_str!("data/pic32.c");

fn arch_of(bin: &LoadedBinary) -> &'static dyn Arch {
    match bin.arch {
        fg_core::ArchId::Aarch64 => &fg_arch_arm64::ARM64,
        id => fg_arch_x86::X86::for_arch(id).unwrap(),
    }
}

/// How the found references compare with the code relocations.
#[derive(Default)]
struct Oracle {
    /// Relocated instructions the CFG reached.
    reached: usize,
    /// Relocation sites in code the CFG did not recover.
    unreached: Vec<u64>,
    /// Reached relocated instructions with no reference: (instruction, relocation type).
    missing: Vec<(u64, String)>,
    /// Relocations whose target can be computed, checked.
    targets: usize,
    /// Those whose target no reference from the instruction has:
    /// (instruction, expected, found).
    wrong: Vec<(u64, u64, Vec<u64>)>,
    /// Data references out of `.text` from an instruction with no relocation:
    /// (instruction, target, kind).
    unrelocated: Vec<(u64, u64, &'static str)>,
}

fn oracle(bytes: &[u8]) -> Oracle {
    let bin = fg_loader::load(bytes, &LoadOptions::default()).unwrap();
    let arch = arch_of(&bin);
    let mut store = FactStore::new();
    seeds::add_seed_facts(&bin, &mut store).unwrap();
    let g = cfg::recover(&bin, bytes, arch, Mode::Native, &mut store).unwrap();
    let refs = xrefs::collect(&bin, bytes, arch, Mode::Native, &g);

    // Every decoded instruction: start → end.
    let text = bin.sections.iter().find(|s| s.name == ".text").unwrap();
    let text = (text.va.unwrap().0, text.va.unwrap().0 + text.size);
    let mut insns: BTreeMap<u64, u64> = BTreeMap::new();
    for f in g.functions.values() {
        for (&start, b) in &f.blocks {
            let mut va = start;
            for _ in 0..b.insns {
                let Some(code) = section_bytes(&bin, bytes, va.0) else {
                    break;
                };
                let Ok(i) = arch.decode(code, va, Mode::Native) else {
                    break;
                };
                insns.insert(va.0, i.end().0);
                va = i.end();
            }
        }
    }
    let containing = |p: u64| {
        insns
            .range(..=p)
            .next_back()
            .filter(|&(_, &end)| p < end)
            .map(|(&s, &e)| (s, e))
    };
    let symbol = |r: &fg_loader::Relocation| -> Option<u64> {
        let s = r.symbol?;
        bin.symbols
            .iter()
            .find(|x| x.table == s.table && x.index == s.index && x.defined)
            .map(|x| x.va.0)
    };

    let plt: Vec<(u64, u64)> = bin
        .sections
        .iter()
        .filter(|s| s.name.starts_with(".plt"))
        .filter_map(|s| Some((s.va?.0, s.va?.0 + s.size)))
        .collect();
    let in_plt = |va: u64| plt.iter().any(|&(a, b)| va >= a && va < b);
    let mut o = Oracle::default();
    let mut relocated_insns = std::collections::BTreeSet::new();
    for r in bin
        .relocations
        .iter()
        .filter(|r| r.table.starts_with(".rela.text") || r.table.starts_with(".rel.text"))
    {
        let Some(p) = r.va.map(|v| v.0) else { continue };
        let ty = r.type_name.unwrap_or("?").to_string();
        // An `adrp` computes a page: the reference is made where the pair
        // completes the address, which has a relocation of its own.
        if matches!(
            ty.as_str(),
            "R_AARCH64_ADR_PREL_PG_HI21"
                | "R_AARCH64_ADR_PREL_PG_HI21_NC"
                | "R_AARCH64_ADR_GOT_PAGE"
        ) {
            continue;
        }
        let Some((insn, end)) = containing(p) else {
            o.unreached.push(p);
            continue;
        };
        relocated_insns.insert(insn);
        o.reached += 1;
        let found: Vec<u64> = refs.from(Va(insn)).map(|x| x.to.0).collect();
        // A weak symbol nobody defines is 0, so an absolute relocation against
        // it stores a null constant, not an address in the file (older
        // `crtbegin.o`: `mov $_ITM_registerTMCloneTable, %eax`).
        let weak_null = matches!(ty.as_str(), "R_X86_64_32" | "R_X86_64_32S" | "R_X86_64_64")
            && r.addend.unwrap_or(0) == 0
            && r.symbol.is_some_and(|s| {
                bin.symbols.iter().any(|x| {
                    x.table == s.table
                        && x.index == s.index
                        && !x.defined
                        && x.binding == SymbolBinding::Weak
                        && x.va.0 == 0
                })
            });
        if found.is_empty() && !weak_null {
            o.missing.push((insn, ty.clone()));
            continue;
        }
        let a = r.addend.unwrap_or(0) as u64;
        let expected = match ty.as_str() {
            "R_X86_64_PC32" | "R_X86_64_PLT32" => {
                symbol(r).map(|s| s.wrapping_add(a).wrapping_add(end - p))
            }
            "R_X86_64_32" | "R_X86_64_32S" | "R_X86_64_64" => symbol(r).map(|s| s.wrapping_add(a)),
            // The low 12 bits completing an `adrp` pair, and PC-relative
            // branches and literals: the whole address.
            "R_AARCH64_ADD_ABS_LO12_NC"
            | "R_AARCH64_LDST8_ABS_LO12_NC"
            | "R_AARCH64_LDST16_ABS_LO12_NC"
            | "R_AARCH64_LDST32_ABS_LO12_NC"
            | "R_AARCH64_LDST64_ABS_LO12_NC"
            | "R_AARCH64_LDST128_ABS_LO12_NC"
            | "R_AARCH64_CALL26"
            | "R_AARCH64_JUMP26"
            | "R_AARCH64_CONDBR19"
            | "R_AARCH64_TSTBR14"
            | "R_AARCH64_ADR_PREL_LO21"
            | "R_AARCH64_LD_PREL_LO19" => symbol(r).map(|s| s.wrapping_add(a)),
            _ => None,
        };
        // An undefined symbol (an import) has no address in the file.
        if let Some(e) = expected.filter(|_| symbol(r).is_some_and(|s| s != 0)) {
            o.targets += 1;
            // In a shared library a call to an exported function goes through
            // its PLT stub (another file may replace the function).
            let via_plt = matches!(
                ty.as_str(),
                "R_X86_64_PLT32" | "R_AARCH64_CALL26" | "R_AARCH64_JUMP26"
            ) && found.iter().any(|&f| in_plt(f));
            if !found.contains(&e) && !via_plt {
                o.wrong.push((insn, e, found));
            }
        }
    }
    for x in refs.all() {
        let data = matches!(
            x.kind,
            XrefKind::Read | XrefKind::Write | XrefKind::ReadWrite | XrefKind::Address
        );
        let inside_text = x.to.0 >= text.0 && x.to.0 < text.1;
        let from_text = x.from.0 >= text.0 && x.from.0 < text.1;
        if !(data && from_text && !inside_text) || relocated_insns.contains(&x.from.0) {
            continue;
        }
        // An address built in a register (a jump table's base, read at an
        // index) was relocated where the register was set: the same target
        // from a relocated instruction of the same function.
        let relocated_ref = |to: Va| {
            refs.to(to)
                .iter()
                .any(|y| y.function == x.function && relocated_insns.contains(&y.from.0))
        };
        let built = match x.via {
            Via::Register => relocated_ref(x.to),
            // A base loaded from a GOT slot: the slot was read by a relocated
            // instruction.
            Via::Slot(slot) => relocated_ref(slot),
            _ => false,
        };
        if !built {
            o.unrelocated.push((x.from.0, x.to.0, x.kind.name()));
        }
    }
    o
}

/// The file bytes from `va` to the end of its section.
fn section_bytes<'a>(bin: &LoadedBinary, bytes: &'a [u8], va: u64) -> Option<&'a [u8]> {
    let s = bin
        .sections
        .iter()
        .find(|s| s.va.is_some_and(|v| va >= v.0 && va < v.0 + s.file_size) && s.perms.execute)?;
    let off = s.file_offset.0 + (va - s.va?.0);
    let end = s.file_offset.0 + s.file_size;
    bytes.get(usize::try_from(off).ok()?..usize::try_from(end).ok()?)
}

fn out_dir() -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("xrefs");
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn every_code_relocation_is_a_reference() {
    let dir = out_dir();
    let src = dir.join("program.c");
    std::fs::write(&src, PROGRAM).unwrap();
    let mut built = 0;
    let mut failures = Vec::new();
    for cc in ["gcc", "clang"] {
        for (kind, link) in [
            ("pie", &["-pie", "-fPIE"][..]),
            ("so", &["-shared", "-fPIC"][..]),
            ("exe", &["-no-pie", "-fno-pie"][..]),
        ] {
            let out = dir.join(format!("{cc}-{kind}"));
            let st = Command::new(cc)
                .args(["-O2", "-fcf-protection=full", "-Wl,--emit-relocs", "-o"])
                .arg(&out)
                .args(link)
                .arg(&src)
                .status();
            if !matches!(st, Ok(s) if s.success()) {
                eprintln!("note: {cc} unavailable or failed; skipped");
                continue;
            }
            built += 1;
            let o = oracle(&std::fs::read(&out).unwrap());
            eprintln!(
                "{cc}-{kind}: {} relocated instructions reached ({} not), {} without a reference, \
                 {}/{} targets right, {} data references without a relocation",
                o.reached,
                o.unreached.len(),
                o.missing.len(),
                o.targets - o.wrong.len(),
                o.targets,
                o.unrelocated.len()
            );
            // With its symbols, every function of the program is recovered.
            if !o.unreached.is_empty() {
                failures.push(format!("{cc}-{kind}: not reached {:x?}", o.unreached));
            }
            if !o.missing.is_empty() {
                failures.push(format!("{cc}-{kind}: no reference from {:x?}", o.missing));
            }
            if !o.wrong.is_empty() {
                failures.push(format!("{cc}-{kind}: wrong targets {:x?}", o.wrong));
            }
            if !o.unrelocated.is_empty() {
                failures.push(format!("{cc}-{kind}: unrelocated {:x?}", o.unrelocated));
            }
        }
    }
    assert!(built > 0 || std::env::var_os("CI").is_none(), "no compiler");
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The linker that ships with Rust (it links any target).
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
fn every_aarch64_code_relocation_is_a_reference() {
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
    let mut failures = Vec::new();
    for (kind, cflags, lflags) in [
        ("pie", &["-fPIE"][..], &["-pie"][..]),
        ("exe", &["-fno-pic"][..], &["-no-pie"][..]),
    ] {
        let obj = dir.join(format!("prog-{kind}.o"));
        let out = dir.join(format!("prog-{kind}"));
        assert!(cc(&prog, &obj, cflags), "{kind}: compile");
        assert!(
            run(Command::new(&lld)
                .args([
                    "-flavor",
                    "gnu",
                    "-e",
                    "_start",
                    "-z",
                    "now",
                    "--emit-relocs"
                ])
                .args(lflags)
                .arg("-o")
                .arg(&out)
                .arg(&obj)
                .arg(&libdep)),
            "{kind}: link"
        );
        let o = oracle(&std::fs::read(&out).unwrap());
        eprintln!(
            "aarch64-{kind}: {} relocated instructions reached ({} not), {} without a reference, \
             {}/{} targets right, {} data references without a relocation",
            o.reached,
            o.unreached.len(),
            o.missing.len(),
            o.targets - o.wrong.len(),
            o.targets,
            o.unrelocated.len()
        );
        for (what, bad) in [
            ("not reached", format!("{:x?}", o.unreached)),
            ("no reference from", format!("{:x?}", o.missing)),
            ("wrong targets", format!("{:x?}", o.wrong)),
            ("unrelocated", format!("{:x?}", o.unrelocated)),
        ] {
            if bad != "[]" {
                failures.push(format!("aarch64-{kind}: {what} {bad}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn x86_32_pic_reaches_globals_through_the_got_pointer() {
    let Some(lld) = rust_lld() else {
        eprintln!("note: rust-lld not found; skipped");
        return;
    };
    let dir = out_dir().join("pic32");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("pic32.c");
    std::fs::write(&src, PIC32).unwrap();
    let run = |cmd: &mut Command| matches!(cmd.status(), Ok(s) if s.success());
    let mut failures = Vec::new();
    for cc in ["gcc", "clang"] {
        let obj = dir.join(format!("{cc}.o"));
        let out = dir.join(format!("{cc}.so"));
        if !run(Command::new(cc)
            .args([
                "-m32",
                "-O2",
                "-fPIC",
                "-ffreestanding",
                "-nostdlib",
                "-c",
                "-o",
            ])
            .arg(&obj)
            .arg(&src))
        {
            eprintln!("note: {cc} cannot build 32-bit code; skipped");
            continue;
        }
        assert!(
            run(Command::new(&lld)
                .args([
                    "-flavor",
                    "gnu",
                    "-m",
                    "elf_i386",
                    "-shared",
                    "--emit-relocs",
                    "-o"
                ])
                .arg(&out)
                .arg(&obj)),
            "{cc}: link"
        );
        let bytes = std::fs::read(&out).unwrap();
        let o = oracle(&bytes);
        eprintln!(
            "{cc}-pic32: {} relocated instructions reached ({} not), {} without a reference, \
             {} data references without a relocation",
            o.reached,
            o.unreached.len(),
            o.missing.len(),
            o.unrelocated.len()
        );
        for (what, bad) in [
            ("not reached", format!("{:x?}", o.unreached)),
            ("no reference from", format!("{:x?}", o.missing)),
            ("unrelocated", format!("{:x?}", o.unrelocated)),
        ] {
            if bad != "[]" {
                failures.push(format!("{cc}-pic32: {what} {bad}"));
            }
        }
        // The globals themselves, not only their GOT slots.
        let bin = fg_loader::load(&bytes, &LoadOptions::default()).unwrap();
        let arch = arch_of(&bin);
        let mut store = FactStore::new();
        seeds::add_seed_facts(&bin, &mut store).unwrap();
        let g = cfg::recover(&bin, &bytes, arch, Mode::Native, &mut store).unwrap();
        let refs = xrefs::collect(&bin, &bytes, arch, Mode::Native, &g);
        let kinds = |name: &str| -> Vec<&'static str> {
            let s = bin
                .symbols
                .iter()
                .find(|s| s.name == name && s.defined)
                .unwrap();
            refs.to_range(s.va, Va(s.va.0 + s.size.max(1)))
                .iter()
                .map(|x| x.kind.name())
                .collect()
        };
        let counter = kinds("counter");
        // `counter += x` is one read/write, or a read and a write; `reset`
        // writes it.
        if !counter.contains(&"write")
            || !(counter.contains(&"read") || counter.contains(&"read/write"))
        {
            failures.push(format!("{cc}-pic32: counter: {counter:?}"));
        }
        let table = kinds("table");
        if !table.contains(&"read") {
            failures.push(format!("{cc}-pic32: table: {table:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
