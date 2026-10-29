//! The disassembly listing on AArch64 files: ELF shared library (lazy PLT),
//! static executable, object file and a PE32+ ARM64 DLL, built here with clang
//! and the LLD linker Rust toolchains ship (`rust-lld`). Instruction addresses
//! and bytes are checked against `llvm-objdump -d`. Missing tools skip with a note.
#![allow(missing_docs)]

use fg_service::Session;
use fg_service::disasm::{Line, Options, Target};
use fg_service::ir::{Flow, tokens_text};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const PROGRAM_C: &str = r#"
extern int puts(const char *);
extern void abort(void);
int counter;
int add(int a, int b) { return a + b; }
long sum(const long *v, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) s += v[i];
    return s;
}
int classify(int x) {
    switch (x) {
    case 0: return 10; case 1: return 11; case 2: return 13; case 3: return 17;
    case 4: return 19; case 5: return 23; case 6: return 29; default: return -1;
    }
}
int main(int argc, char **argv) {
    switch (argc) {
    case 1: puts("one"); break;
    case 2: puts("two"); break;
    case 3: abort();
    default: counter++;
    }
    return add(argc, counter) + classify(argc);
}
"#;

/// A function with SIMD, atomics, system and pointer-authentication instructions.
const EXTRA_S: &str = r"
    .text
    .globl extra
    .type extra, %function
extra:
    paciasp
    ldaxr   x1, [x0]
    stlxr   w2, x1, [x0]
    ldadd   w3, w4, [x0]
    add     v0.4s, v1.4s, v2.4s
    fmla    v0.2d, v1.2d, v2.d[1]
    mrs     x5, tpidr_el0
    dmb     ish
    autiasp
    ret
    .size extra, .-extra
";

struct Fixtures {
    so: PathBuf,
    exe: PathBuf,
    obj: PathBuf,
    dll: PathBuf,
}

/// LLD from the Rust toolchain: `<sysroot>/lib/rustlib/<host>/bin/gcc-ld/<name>`.
fn rust_lld(name: &str) -> Option<PathBuf> {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout).ok()?.trim());
    let host = Command::new("rustc").args(["-vV"]).output().ok()?;
    let host = String::from_utf8(host.stdout).ok()?;
    let host = host
        .lines()
        .find_map(|l| l.strip_prefix("host: "))?
        .to_string();
    let bin = sysroot.join("lib/rustlib").join(host).join("bin");
    let p = if name == "rust-lld" {
        bin.join(name)
    } else {
        bin.join("gcc-ld").join(name)
    };
    p.exists().then_some(p)
}

fn fixtures() -> Option<&'static Fixtures> {
    static F: OnceLock<Option<Fixtures>> = OnceLock::new();
    F.get_or_init(|| {
        let ld = rust_lld("ld.lld");
        let lld = rust_lld("rust-lld");
        let (Some(ld), Some(lld)) = (ld, lld) else {
            eprintln!("note: rust-lld not found; AArch64 listing fixtures skipped");
            return None;
        };
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("disasm-arm64");
        let _ = std::fs::create_dir_all(&dir);
        let c = dir.join("program.c");
        let s = dir.join("extra.s");
        std::fs::write(&c, PROGRAM_C).ok()?;
        std::fs::write(&s, EXTRA_S).ok()?;
        let f = Fixtures {
            so: dir.join("program.so"),
            exe: dir.join("program"),
            obj: dir.join("extra.o"),
            dll: dir.join("program.dll"),
        };
        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("note: clang not found; AArch64 listing tests skipped");
            return None;
        }
        // With clang and LLD present, a fixture that fails to build is a test failure.
        let run = |cmd: &mut Command| {
            let out = cmd.output().expect("run clang / rust-lld");
            assert!(
                out.status.success(),
                "{cmd:?} failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            true
        };
        let ld_path = format!("--ld-path={}", ld.display());
        let elf = [
            "--target=aarch64-linux-gnu",
            "-march=armv8.5-a+lse",
            "-O1",
            "-nostdlib",
            "-fuse-ld=lld",
            &ld_path,
        ];
        let pe_obj = dir.join("program.obj");
        let built = run(Command::new("clang")
            .args(elf)
            .args(["-fPIC", "-shared", "-Wl,-z,lazy"])
            .arg(&c)
            .arg(&s)
            .arg("-o")
            .arg(&f.so))
            && run(Command::new("clang")
                .args(elf)
                .args([
                    "-no-pie",
                    "-Wl,-e,main",
                    "-Wl,--unresolved-symbols=ignore-all",
                ])
                .arg(&c)
                .arg("-o")
                .arg(&f.exe))
            && run(Command::new("clang")
                .args(["--target=aarch64-linux-gnu", "-march=armv8.5-a+lse", "-c"])
                .arg(&s)
                .arg("-o")
                .arg(&f.obj))
            && run(Command::new("clang")
                .args(["--target=aarch64-pc-windows-msvc", "-O1", "-c"])
                .arg(&c)
                .arg("-o")
                .arg(&pe_obj))
            && run(Command::new(&lld)
                .args([
                    "-flavor",
                    "link",
                    "/dll",
                    "/noentry",
                    "/machine:arm64",
                    "/export:add",
                    "/force:unresolved",
                ])
                .arg(format!("/out:{}", f.dll.display()))
                .arg(&pe_obj));
        built.then_some(f)
    })
    .as_ref()
}

fn listing(path: &Path, target: &Target) -> Vec<Line> {
    let s = Session::open(path).unwrap();
    s.disassemble(target, Options::default()).unwrap()
}

fn insn_text(line: &Line) -> Option<(u64, String)> {
    match line {
        Line::Insn(i) => Some((i.insn.va.0, tokens_text(&i.tokens))),
        _ => None,
    }
}

#[test]
fn plt_stubs_are_named() {
    let Some(fx) = fixtures() else { return };
    let lines = listing(&fx.so, &Target::Section(".plt".into()));
    let labels: Vec<&String> = lines
        .iter()
        .filter_map(|l| match l {
            Line::Label { names, .. } => names.first(),
            _ => None,
        })
        .collect();
    assert!(labels.iter().any(|n| *n == "puts@plt"), "{labels:?}");
    assert!(labels.iter().any(|n| *n == "abort@plt"), "{labels:?}");

    // Calls name their stubs.
    let main = listing(&fx.so, &Target::Symbol("main".into()));
    let calls: Vec<String> = main
        .iter()
        .filter_map(insn_text)
        .map(|(_, t)| t)
        .filter(|t| t.starts_with("bl "))
        .collect();
    assert!(calls.iter().any(|t| t.ends_with("<puts@plt>")), "{calls:?}");
    assert!(
        calls.iter().any(|t| t.ends_with("<abort@plt>")),
        "{calls:?}"
    );
}

#[test]
fn functions_flow_and_names() {
    let Some(fx) = fixtures() else { return };
    let lines = listing(&fx.exe, &Target::Symbol("main".into()));
    let insns: Vec<&fg_service::disasm::InsnLine> = lines
        .iter()
        .filter_map(|l| match l {
            Line::Insn(i) => Some(i),
            _ => None,
        })
        .collect();
    assert!(insns.len() > 10);
    assert!(
        insns
            .iter()
            .all(|i| i.insn.va.0 % 4 == 0 && i.insn.len() == 4)
    );
    assert!(insns.iter().any(|i| i.insn.flow == Flow::Return));
    assert!(
        insns
            .iter()
            .any(|i| matches!(i.insn.flow, Flow::Call { .. }))
    );
    // Mapping symbols ($x, $d) are not used as names.
    assert!(lines.iter().all(|l| !format!("{l:?}").contains("<$")));

    // The object file: one function from the assembly, every line decoded.
    let obj = listing(&fx.obj, &Target::CodeSections);
    let texts: Vec<String> = obj.iter().filter_map(insn_text).map(|(_, t)| t).collect();
    assert_eq!(texts.first().map(String::as_str), Some("paciasp"));
    assert!(
        texts.iter().any(|t| t.starts_with("ldadd w3, w4, [x0]")),
        "{texts:?}"
    );
    assert!(
        texts.iter().any(|t| t == "fmla v0.2d, v1.2d, v2.d[1]"),
        "{texts:?}"
    );
    assert!(texts.iter().any(|t| t == "mrs x5, tpidr_el0"), "{texts:?}");
    assert!(!obj.iter().any(|l| matches!(l, Line::Bad { .. })));
}

#[test]
fn pe_arm64() {
    let Some(fx) = fixtures() else { return };
    let s = Session::open(&fx.dll).unwrap();
    assert!(s.arch().is_some());
    let lines = s
        .disassemble(&Target::Symbol("add".into()), Options::default())
        .unwrap();
    let texts: Vec<String> = lines.iter().filter_map(insn_text).map(|(_, t)| t).collect();
    // A leaf function has no exception-table entry and the export no size, so
    // the listing runs on past it; its own two instructions come first.
    assert_eq!(texts[..2], ["add w0, w1, w0", "ret"]);
}

/// Every instruction llvm-objdump prints is in the listing at the same address
/// with the same bytes and mnemonic (the operand text is checked word by word
/// against llvm-mc in fg-arch-arm64's oracle).
#[test]
fn agrees_with_llvm_objdump() {
    let Some(fx) = fixtures() else { return };
    let objdump = std::env::var("FULG_LLVM_OBJDUMP").unwrap_or_else(|_| "llvm-objdump".into());
    for path in [&fx.so, &fx.exe, &fx.dll] {
        let Ok(out) = Command::new(&objdump)
            .args(["-d", "--mattr=+all"])
            .arg(path)
            .output()
        else {
            eprintln!("note: llvm-objdump not found; skipped");
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        // "   104e0: 10 01 00 90  \tadrp\tx16, ..."
        let mut theirs: BTreeMap<u64, (u32, String)> = BTreeMap::new();
        for line in text.lines() {
            let Some((addr, rest)) = line.trim_start().split_once(':') else {
                continue;
            };
            let Ok(va) = u64::from_str_radix(addr, 16) else {
                continue;
            };
            let mut fields = rest.split('\t').filter(|f| !f.trim().is_empty());
            let Some(encoding) = fields.next() else {
                continue;
            };
            // llvm-objdump prints an A64 encoding as one 32-bit word.
            let Ok(word) = u32::from_str_radix(encoding.trim(), 16) else {
                continue;
            };
            let Some(mnemonic) = fields.next() else {
                continue;
            };
            if encoding.trim().len() != 8
                || mnemonic.starts_with('.')
                || mnemonic.starts_with("<unknown>")
            {
                continue;
            }
            theirs.insert(va, (word, mnemonic.trim().to_string()));
        }
        assert!(
            theirs.len() > 20,
            "{}: llvm-objdump listed {}",
            path.display(),
            theirs.len()
        );
        let ours: BTreeMap<u64, (u32, String)> = listing(path, &Target::CodeSections)
            .iter()
            .filter_map(|l| match l {
                Line::Insn(i) => {
                    let b: [u8; 4] = i.insn.bytes.as_slice().try_into().ok()?;
                    let text = tokens_text(&i.tokens);
                    let mnemonic = text.split_whitespace().next()?.to_string();
                    Some((i.insn.va.0, (u32::from_le_bytes(b), mnemonic)))
                }
                _ => None,
            })
            .collect();
        for (va, (word, mnemonic)) in &theirs {
            let Some((w, m)) = ours.get(va) else {
                panic!(
                    "{}: {va:#x} {mnemonic} missing from the listing",
                    path.display()
                );
            };
            assert_eq!(w, word, "{}: {va:#x}", path.display());
            // llvm-objdump and Arm differ on a few preferred aliases (see the
            // decoder oracle); the mnemonic must match otherwise.
            let aliases = [("bfc", "bfi"), ("sxtl", "sshll"), ("uxtl", "ushll")];
            assert!(
                m == mnemonic || aliases.contains(&(m.as_str(), mnemonic.as_str())),
                "{}: {va:#x} ours {m}, llvm-objdump {mnemonic}",
                path.display()
            );
        }
    }
}
