//! Oracle tests: compare the loader against independent tools on real binaries.
//!
//! * `readelf` (GNU binutils) for every parsed value: file type, entry point,
//!   program-header count and every program-header field, dynamic flags.
//!   Plus every section header (`readelf -S`) and every symbol in both symbol
//!   tables, with versions (`readelf -s`).
//!   Plus every relocation (`readelf -r`, RELR decoded), every note and GNU
//!   property (`readelf -n`), and the library names and search paths (`readelf -d`).
//! * `checksec` (Go version, if installed) for the PIE / NX / RELRO / canary /
//!   FORTIFY / CFI / separate-code / RPATH / RUNPATH verdicts and the symbol count.
//!
//! Inputs: system binaries that exist on this machine, plus binaries compiled on
//! the fly with different hardening flags. Anything unavailable is skipped with a
//! note, so the suite also runs on minimal CI machines.

use fg_loader::{BinaryKind, LoadOptions, LoadedBinary, Verdict, load};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const PROGRAM: &str = "int main(void) { return 0; }\n";
const LIBRARY: &str = "int fulgurite_test_fn(void) { return 1; }\n";
/// Has a local buffer (gets a canary) and calls fortifiable functions.
const BUFFER: &str = "#include <stdio.h>\n#include <string.h>\n\
int main(int argc, char **argv) { char buf[16]; strcpy(buf, argc > 1 ? argv[1] : \"x\");\n\
printf(\"%s\\n\", buf); return 0; }\n";

/// Many pointers in data: plenty of relative relocations to pack with RELR.
const POINTERS: &str = "#include <stdio.h>\n\
static const char *names[] = {\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\",\"j\",\"k\",\"l\",\"m\",\n\
\"n\",\"o\",\"p\",\"q\",\"r\",\"s\",\"t\",\"u\",\"v\",\"w\",\"x\",\"y\",\"z\",0};\n\
static int (*fns[])(const char *) = {puts, puts, puts};\n\
int main(int argc, char **argv) { (void)argv; return fns[argc % 3](names[argc]); }\n";
/// Calls, globals and string data without any header, so it builds for -m32 even
/// where 32-bit libc headers are not installed.
const OBJECT32: &str = "extern int ext_var; int ext_fn(int);\n\
static const char *msg = \"hi\";\n\
int f(int x) { return ext_fn(x) + ext_var + msg[0]; }\n";
/// Non-PIC 32-bit code in a shared library: needs text relocations.
const TEXTREL: &str = "int counter; int bump(void) { return ++counter; }\n";

/// System files to check when present (distro paths differ).
const SYSTEM: &[&str] = &[
    "/bin/cat",
    "/bin/ls",
    "/bin/sh",
    "/usr/bin/env",
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/libm.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
];

/// Compiler variants: (name, source, extra gcc arguments).
const VARIANTS: &[(&str, &str, &[&str])] = &[
    ("default", PROGRAM, &[]),
    ("no_pie", PROGRAM, &["-no-pie", "-fno-pie"]),
    ("static", PROGRAM, &["-static"]),
    ("static_pie", PROGRAM, &["-static-pie"]),
    ("execstack", PROGRAM, &["-z", "execstack"]),
    ("norelro", PROGRAM, &["-Wl,-z,norelro"]),
    ("lazy", PROGRAM, &["-Wl,-z,lazy", "-Wl,-z,relro"]),
    ("shared", LIBRARY, &["-shared", "-fPIC"]),
    ("object", LIBRARY, &["-c"]),
    ("cet_full", BUFFER, &["-fcf-protection=full"]),
    ("cet_branch", BUFFER, &["-fcf-protection=branch"]),
    ("cet_none", BUFFER, &["-fcf-protection=none"]),
    (
        "rpath",
        PROGRAM,
        &[
            "-Wl,-rpath,/opt/fulgurite-test/lib",
            "-Wl,--disable-new-dtags",
        ],
    ),
    (
        "runpath_origin",
        PROGRAM,
        &["-Wl,-rpath,$ORIGIN/../lib", "-Wl,--enable-new-dtags"],
    ),
    (
        "runpath_relative",
        PROGRAM,
        &["-Wl,-rpath,lib::/usr/lib", "-Wl,--enable-new-dtags"],
    ),
    ("relr", POINTERS, &["-Wl,-z,pack-relative-relocs"]),
    ("pointers", POINTERS, &[]),
    ("noseparate", PROGRAM, &["-Wl,-z,noseparate-code"]),
    ("emit_relocs", BUFFER, &["-Wl,--emit-relocs"]),
    ("object32", OBJECT32, &["-m32", "-c"]),
    ("object32_pic", OBJECT32, &["-m32", "-c", "-fPIC"]),
    (
        "shared32",
        LIBRARY,
        &["-m32", "-shared", "-nostdlib", "-fPIC"],
    ),
    (
        "textrel32",
        TEXTREL,
        &["-m32", "-shared", "-nostdlib", "-fno-pic", "-Wl,-z,notext"],
    ),
    ("buf_default", BUFFER, &["-fstack-protector-strong"]),
    ("buf_nocanary", BUFFER, &["-fno-stack-protector"]),
    (
        "buf_fortify",
        BUFFER,
        &["-O2", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong"],
    ),
];

/// The only functions checksec 3.2.0 counts for FORTIFY: the hardcoded
/// `supportedFuncs` list in its `pkg/checksec/fortify.go`. Fulgurite reports all
/// fortifiable glibc functions; the oracle compares counts over this subset only.
const CHECKSEC_FORTIFY_FUNCS: &[&str] = &[
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "snprintf",
    "sprintf",
    "vsnprintf",
    "vsprintf",
    "fprintf",
    "printf",
    "vfprintf",
    "vprintf",
];

/// The function a FORTIFY evidence line is about: `imports __memcpy_chk@GLIBC_2.3.4
/// (fortified)` -> `memcpy`.
fn evidence_function(text: &str) -> &str {
    let name = text
        .trim_start_matches("imports ")
        .split(['@', ' '])
        .next()
        .unwrap_or("");
    name.strip_prefix("__")
        .and_then(|n| n.strip_suffix("_chk"))
        .unwrap_or(name)
}

/// Copies of a built variant post-processed by binutils: (name, source variant, tool, args).
const DERIVED: &[(&str, &str, &str, &[&str])] = &[
    ("stripped", "buf_default", "strip", &[]),
    (
        "noshdr",
        "buf_default",
        "objcopy",
        &["--strip-section-headers"],
    ),
];

/// Path of a built input by variant name, if it was built.
fn variant(name: &str) -> Option<&'static PathBuf> {
    inputs()
        .iter()
        .find(|p| p.file_name().is_some_and(|f| f == name))
}

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Inputs are built once per test process; both oracle tests share them.
fn inputs() -> &'static [PathBuf] {
    static INPUTS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    INPUTS.get_or_init(build_inputs)
}

fn build_inputs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = SYSTEM
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .collect();
    if !tool_available("gcc") {
        eprintln!("note: gcc not found, compiled variants skipped");
        return out;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("oracle");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, src, args) in VARIANTS {
        let c = dir.join(format!("{name}.c"));
        std::fs::write(&c, src).unwrap();
        let out_path = dir.join(name);
        let status = Command::new("gcc")
            .args(*args)
            .arg(&c)
            .arg("-o")
            .arg(&out_path)
            .output();
        match status {
            Ok(o) if o.status.success() => out.push(out_path),
            _ => eprintln!("note: could not build variant {name}; skipped"),
        }
    }
    for (name, from, tool, args) in DERIVED {
        let src = dir.join(from);
        let dst = dir.join(name);
        if !src.is_file() || std::fs::copy(&src, &dst).is_err() {
            continue;
        }
        match Command::new(tool).args(*args).arg(&dst).output() {
            Ok(o) if o.status.success() => out.push(dst),
            _ => eprintln!("note: {tool} {args:?} unavailable; variant {name} skipped"),
        }
    }
    out
}

fn load_file(path: &Path) -> LoadedBinary {
    let bytes = std::fs::read(path).unwrap();
    load(&bytes, &LoadOptions::default()).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("not hex: {s}"))
}

/// One row of `readelf -W -l`.
#[derive(Debug, Default)]
struct ReadelfPhdr {
    ty: String,
    /// (offset, vaddr, paddr, filesz, memsz, align)
    numbers: (u64, u64, u64, u64, u64, u64),
    /// Flags as readelf prints them, spaces removed (e.g. "RE").
    flags: String,
}

/// The parts of `readelf -W -h -l -d` output that the loader must agree with.
#[derive(Debug, Default)]
struct Readelf {
    e_type: String,
    entry: u64,
    phnum: u64,
    phdrs: Vec<ReadelfPhdr>,
    flags: Option<String>,
    flags_1: Option<String>,
    bind_now: bool,
    needed: Vec<String>,
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
}

/// The text between the first `[` and the last `]`.
fn bracketed(t: &str) -> String {
    let a = t.find('[').map_or(0, |i| i + 1);
    let b = t.rfind(']').unwrap_or(t.len());
    t[a..b].to_string()
}

fn readelf(path: &Path) -> Readelf {
    let out = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["-W", "-h", "-l", "-d"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut r = Readelf::default();
    let mut in_phdrs = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Type:") {
            r.e_type = v.split_whitespace().next().unwrap_or("").to_string();
        } else if let Some(v) = t.strip_prefix("Entry point address:") {
            r.entry = hex(v.trim());
        } else if let Some(v) = t.strip_prefix("Number of program headers:") {
            r.phnum = v.split_whitespace().next().unwrap().parse().unwrap();
        } else if t.starts_with("Type") && t.contains("Offset") && t.contains("VirtAddr") {
            in_phdrs = true;
        } else if in_phdrs {
            if t.is_empty() {
                in_phdrs = false;
            } else if !t.starts_with('[') {
                let tok: Vec<&str> = t.split_whitespace().collect();
                let n = tok.len();
                // Columns: 0 type, 1 offset, 2 vaddr, 3 paddr, 4 filesz, 5 memsz, 6.. flags, last align.
                let flags: String = tok[6..n - 1].concat();
                r.phdrs.push(ReadelfPhdr {
                    ty: tok[0].to_string(),
                    numbers: (
                        hex(tok[1]),
                        hex(tok[2]),
                        hex(tok[3]),
                        hex(tok[4]),
                        hex(tok[5]),
                        hex(tok[n - 1]),
                    ),
                    flags,
                });
            }
        } else if t.contains("(FLAGS)") {
            r.flags = Some(t.split(')').nth(1).unwrap_or("").trim().to_string());
        } else if t.contains("(FLAGS_1)") {
            r.flags_1 = Some(t.split("Flags:").nth(1).unwrap_or("").trim().to_string());
        } else if t.contains("(BIND_NOW)") {
            r.bind_now = true;
        } else if t.contains("(NEEDED)") {
            r.needed.push(bracketed(t));
        } else if t.contains("(SONAME)") {
            r.soname = Some(bracketed(t));
        } else if t.contains("(RPATH)") {
            r.rpath = Some(bracketed(t));
        } else if t.contains("(RUNPATH)") {
            r.runpath = Some(bracketed(t));
        }
    }
    r
}

fn readelf_flags(perms: fg_core::Perms) -> String {
    let mut s = String::new();
    if perms.read {
        s.push('R')
    }
    if perms.write {
        s.push('W')
    }
    if perms.execute {
        s.push('E')
    }
    s
}

#[test]
fn matches_readelf() {
    if !tool_available("readelf") {
        eprintln!("note: readelf not found, oracle skipped");
        return;
    }
    let files = inputs();
    assert!(!files.is_empty(), "no oracle inputs found");
    for path in files {
        let bin = load_file(path);
        let elf = bin.elf().unwrap();
        let r = readelf(path);
        let ctx = path.display();
        assert_eq!(
            fg_loader::elf::consts::e_type_name(elf.header.e_type.value),
            r.e_type,
            "{ctx}: e_type"
        );
        assert_eq!(elf.header.e_entry.value, r.entry, "{ctx}: entry");
        assert_eq!(u64::from(elf.phnum), r.phnum, "{ctx}: phnum");
        assert_eq!(
            elf.program_headers.len(),
            r.phdrs.len(),
            "{ctx}: program header rows"
        );
        for (p, row) in elf.program_headers.iter().zip(&r.phdrs) {
            if let Some(name) = p.type_name() {
                assert_eq!(name, row.ty, "{ctx}: phdr #{} type", p.index);
            }
            let ours = (
                p.p_offset.value,
                p.p_vaddr.value,
                p.p_paddr.value,
                p.p_filesz.value,
                p.p_memsz.value,
                p.p_align.value,
            );
            assert_eq!(ours, row.numbers, "{ctx}: phdr #{} numbers", p.index);
            assert_eq!(
                readelf_flags(p.perms()),
                row.flags,
                "{ctx}: phdr #{} flags",
                p.index
            );
        }
        let df_bind_now = elf
            .dynamic_entry(30)
            .is_some_and(|d| d.value.value & 0x8 != 0);
        assert_eq!(
            df_bind_now,
            r.flags
                .as_deref()
                .is_some_and(|f| f.split_whitespace().any(|w| w == "BIND_NOW")),
            "{ctx}: DF_BIND_NOW"
        );
        let f1 = elf
            .dynamic_entry(0x6fff_fffb)
            .map(|d| d.value.value)
            .unwrap_or(0);
        let r1 = r.flags_1.clone().unwrap_or_default();
        assert_eq!(
            f1 & 0x1 != 0,
            r1.split_whitespace().any(|w| w == "NOW"),
            "{ctx}: DF_1_NOW"
        );
        assert_eq!(
            f1 & 0x0800_0000 != 0,
            r1.split_whitespace().any(|w| w == "PIE"),
            "{ctx}: DF_1_PIE"
        );
        assert_eq!(
            elf.dynamic_entry(24).is_some(),
            r.bind_now,
            "{ctx}: DT_BIND_NOW"
        );
        let st = &elf.strings;
        let names: Vec<&str> = st.needed.iter().map(|n| n.value.as_str()).collect();
        assert_eq!(names, r.needed, "{ctx}: DT_NEEDED");
        let val = |f: &Option<fg_core::Field<String>>| f.as_ref().map(|f| f.value.clone());
        assert_eq!(val(&st.soname), r.soname, "{ctx}: DT_SONAME");
        assert_eq!(val(&st.rpath), r.rpath, "{ctx}: DT_RPATH");
        assert_eq!(val(&st.runpath), r.runpath, "{ctx}: DT_RUNPATH");
        eprintln!("ok  readelf  {ctx}");
    }
}

fn checksec(path: &Path) -> Option<serde_json::Value> {
    let out = Command::new("checksec")
        .args(["file"])
        .arg(path)
        .args(["--output", "json"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    Some(v.get(0)?.get("checks")?.clone())
}

#[test]
fn matches_checksec() {
    if checksec(Path::new("/bin/sh")).is_none() && checksec(Path::new("/bin/cat")).is_none() {
        eprintln!("note: Go checksec not found, oracle skipped");
        return;
    }
    for path in inputs() {
        let Some(checks) = checksec(path) else {
            continue;
        };
        let bin = load_file(path);
        let ctx = path.display();
        let value = |k: &str| {
            checks
                .get(k)
                .and_then(|c| c.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        let pie = value("pie");
        let expected_pie = match pie.as_str() {
            "PIE Enabled" | "Static PIE" => Some(Verdict::Enabled),
            "PIE Disabled" | "No PIE" => Some(Verdict::Disabled),
            "DSO" | "REL" => Some(Verdict::NotApplicable),
            other => panic!("{ctx}: unmapped checksec PIE value {other:?}; extend the mapping"),
        };
        if let Some(v) = expected_pie {
            // checksec calls a libc that has an interpreter a "DSO"; we infer PIE from the
            // interpreter and say so in the evidence. Accept that documented difference.
            let inferred = bin.kind == BinaryKind::PieExecutable
                && bin
                    .mitigations
                    .pie
                    .evidence
                    .iter()
                    .any(|e| e.text.contains("inferred"));
            if !(inferred && pie == "DSO") {
                assert_eq!(
                    bin.mitigations.pie.verdict, v,
                    "{ctx}: PIE (checksec: {pie})"
                );
            }
        }

        let nx = value("nx");
        match nx.as_str() {
            "NX enabled" => assert_eq!(bin.mitigations.nx.verdict, Verdict::Enabled, "{ctx}: NX"),
            "NX disabled" => assert!(
                matches!(
                    bin.mitigations.nx.verdict,
                    Verdict::Disabled | Verdict::Unknown
                ),
                "{ctx}: NX (checksec: {nx}, ours {:?})",
                bin.mitigations.nx.verdict
            ),
            "N/A" => assert_eq!(
                bin.mitigations.nx.verdict,
                Verdict::NotApplicable,
                "{ctx}: NX"
            ),
            other => panic!("{ctx}: unmapped checksec NX value {other:?}; extend the mapping"),
        }

        if bin.kind != BinaryKind::Relocatable {
            let relro = value("relro");
            let expected = match relro.as_str() {
                "Full RELRO" => Some(Verdict::Enabled),
                "Partial RELRO" => Some(Verdict::Partial),
                "No RELRO" => Some(Verdict::Disabled),
                other => {
                    panic!("{ctx}: unmapped checksec RELRO value {other:?}; extend the mapping")
                }
            };
            if let Some(v) = expected {
                assert_eq!(
                    bin.mitigations.relro.verdict, v,
                    "{ctx}: RELRO (checksec: {relro})"
                );
            }
        }
        let canary = value("canary");
        match canary.as_str() {
            "Canary Found" => assert_eq!(
                bin.mitigations.canary.verdict,
                Verdict::Enabled,
                "{ctx}: canary"
            ),
            "No Canary Found" => assert_eq!(
                bin.mitigations.canary.verdict,
                Verdict::Disabled,
                "{ctx}: canary"
            ),
            other => panic!("{ctx}: unmapped checksec canary value {other:?}; extend the mapping"),
        }

        // checksec counts FORTIFY from section-header symbols, so files without
        // section headers are compared only on what both can see.
        let has_sections = !bin.elf().unwrap().section_headers.is_empty();
        let fortify = value("fortify_source");
        let f = &bin.mitigations.fortify;
        match fortify.as_str() {
            "Yes" => assert_eq!(f.verdict, Verdict::Enabled, "{ctx}: FORTIFY"),
            "No" => assert!(
                matches!(f.verdict, Verdict::Disabled | Verdict::NotApplicable),
                "{ctx}: FORTIFY (checksec No, ours {:?})",
                f.verdict
            ),
            "N/A" => assert!(
                matches!(f.verdict, Verdict::NotApplicable | Verdict::Unknown),
                "{ctx}: FORTIFY (checksec N/A, ours {:?})",
                f.verdict
            ),
            other => panic!("{ctx}: unmapped checksec fortify value {other:?}; extend the mapping"),
        }
        if has_sections && fortify != "N/A" {
            // checksec counts symbols, not functions: memcpy and __memcpy_chk are two.
            let known = |e: &&fg_core::Evidence| {
                CHECKSEC_FORTIFY_FUNCS.contains(&evidence_function(&e.text))
            };
            let fortified = f
                .evidence
                .iter()
                .filter(|e| e.text.ends_with("(fortified)") && known(e))
                .count();
            let plain = f
                .evidence
                .iter()
                .filter(|e| {
                    (e.text.ends_with("never fortified)") || e.text.ends_with("without checks)"))
                        && known(e)
                })
                .count();
            assert_eq!(
                fortified.to_string(),
                value("fortified"),
                "{ctx}: fortified count"
            );
            assert_eq!(
                (fortified + plain).to_string(),
                value("fortifyable"),
                "{ctx}: fortifiable symbol count"
            );
        }

        let cfi = value("cfi");
        let ours = bin.mitigations.cfi.verdict;
        match cfi.as_str() {
            "SHSTK & IBT" => assert_eq!(ours, Verdict::Enabled, "{ctx}: CFI ({cfi})"),
            "SHSTK & NO IBT" | "NO SHSTK & IBT" => {
                assert_eq!(ours, Verdict::Partial, "{ctx}: CFI ({cfi})")
            }
            "NO SHSTK & NO IBT" => assert_eq!(ours, Verdict::Disabled, "{ctx}: CFI ({cfi})"),
            // checksec reads only the `.note.gnu.property` section; without section
            // headers it cannot see the note we read through PT_NOTE.
            "Unknown" if !has_sections => {}
            // No property note at all: we report "not marked" (Disabled), not Unknown.
            "Unknown" => assert_eq!(ours, Verdict::Disabled, "{ctx}: CFI ({cfi})"),
            other => panic!("{ctx}: unmapped checksec CFI value {other:?}; extend the mapping"),
        }

        let sep = value("separate_code");
        let ours = bin.mitigations.separate_code.verdict;
        match sep.as_str() {
            // checksec only checks for a W+X segment; we also check what the code
            // segment maps, so "Enabled" there may be Partial here.
            "Enabled" => assert!(
                matches!(ours, Verdict::Enabled | Verdict::Partial),
                "{ctx}: separate code (checksec {sep}, ours {ours:?})"
            ),
            "WX Segment" => assert_eq!(ours, Verdict::Disabled, "{ctx}: separate code"),
            "N/A" => assert_eq!(ours, Verdict::NotApplicable, "{ctx}: separate code"),
            other => panic!("{ctx}: unmapped checksec separate_code value {other:?}"),
        }

        let st = &bin.elf().unwrap().strings;
        for (key, label, ours) in [
            ("rpath", "RPATH", &st.rpath),
            ("runpath", "RUNPATH", &st.runpath),
        ] {
            let v = value(key);
            if v == format!("No {label}") {
                assert!(ours.is_none(), "{ctx}: {label} (checksec {v})");
            } else {
                assert_eq!(
                    ours.as_ref().map(|f| f.value.clone()),
                    Some(bracketed(&v)),
                    "{ctx}: {label} (checksec {v})"
                );
            }
        }
        let lp = bin.mitigations.library_paths.verdict;
        let paths = format!("{} {}", value("rpath"), value("runpath"));
        if paths.contains("(relative)") || paths.contains("(empty (cwd))") {
            assert_eq!(lp, Verdict::Disabled, "{ctx}: LibPath ({paths})");
        } else if paths.contains("($ORIGIN)") {
            assert_eq!(lp, Verdict::Partial, "{ctx}: LibPath ({paths})");
        }

        let syms = value("symbols");
        let statics = bin
            .symbols
            .iter()
            .filter(|s| s.table == fg_loader::SymbolTable::Static)
            .count();
        if syms == "No Symbols" {
            assert!(
                statics <= 1,
                "{ctx}: symbols (checksec {syms}, ours {statics})"
            );
        } else {
            // Go's debug/elf leaves out the reserved null symbol.
            let n: usize = syms
                .trim_end_matches(" symbols")
                .parse()
                .unwrap_or_else(|_| panic!("{ctx}: unmapped checksec symbols value {syms:?}"));
            assert_eq!(statics - 1, n, "{ctx}: static symbol count");
        }

        eprintln!(
            "ok  checksec {ctx}  pie={pie} nx={nx} relro={} canary={canary} fortify={fortify} \
             cfi={cfi} sepcode={sep} rpath={} runpath={} symbols={syms}",
            value("relro"),
            value("rpath"),
            value("runpath")
        );
    }
}

/// One row of `readelf -W -S`.
#[derive(Debug)]
struct ReadelfSection {
    name: String,
    ty: String,
    /// (address, offset, size, entsize, link, info, align)
    numbers: (u64, u64, u64, u64, u64, u64, u64),
    flags: String,
}

fn readelf_sections(path: &Path) -> Vec<ReadelfSection> {
    let out = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["-W", "-S"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('[') else {
            continue;
        };
        let Some((idx, rest)) = rest.split_once(']') else {
            continue;
        };
        let Ok(idx) = idx.trim().parse::<u32>() else {
            continue;
        }; // header row "[Nr]"
        let tok: Vec<&str> = rest.split_whitespace().collect();
        // Section 0 has no name; every other row starts with its name.
        let (name, tok) = if idx == 0 {
            (String::new(), &tok[..])
        } else {
            (tok[0].to_string(), &tok[1..])
        };
        // type addr off size es [flags] lk inf al
        let (flags, tail) = match tok.len() {
            9 => (tok[5].to_string(), &tok[6..]),
            8 => (String::new(), &tok[5..]),
            n => panic!(
                "{}: unexpected readelf -S row ({n} fields): {t}",
                path.display()
            ),
        };
        let dec = |s: &str| s.parse::<u64>().unwrap();
        rows.push(ReadelfSection {
            name,
            ty: tok[0].to_string(),
            numbers: (
                hex(tok[1]),
                hex(tok[2]),
                hex(tok[3]),
                hex(tok[4]),
                dec(tail[0]),
                dec(tail[1]),
                dec(tail[2]),
            ),
            flags,
        });
    }
    rows
}

#[test]
fn sections_match_readelf() {
    if !tool_available("readelf") {
        return;
    }
    for path in inputs() {
        check_sections(path);
    }
}

/// Every section header of `path` against `readelf -W -S`: name, type, numbers, and
/// the flag letters with their order. Returns the OR of all section flags.
fn check_sections(path: &Path) -> u64 {
    let bin = load_file(path);
    let elf = bin.elf().unwrap();
    let ctx = path.display();
    let rows = readelf_sections(path);
    assert_eq!(
        elf.section_headers.len(),
        rows.len(),
        "{ctx}: section count"
    );
    let machine = elf.header.e_machine.value;
    let osabi = elf.header.ident.osabi.value;
    let mut all_flags = 0;
    for (s, r) in elf.section_headers.iter().zip(&rows) {
        assert_eq!(s.name_str(), r.name, "{ctx}: section #{} name", s.index);
        if let Some(ty) = fg_loader::elf::consts::sh_type_name(s.sh_type.value, machine) {
            assert_eq!(ty, r.ty, "{ctx}: section #{} type", s.index);
        }
        let ours = (
            s.sh_addr.value,
            s.sh_offset.value,
            s.sh_size.value,
            s.sh_entsize.value,
            u64::from(s.sh_link.value),
            u64::from(s.sh_info.value),
            s.sh_addralign.value,
        );
        assert_eq!(ours, r.numbers, "{ctx}: section #{} numbers", s.index);
        let letters = fg_loader::elf::consts::sh_flags_letters(s.sh_flags.value, machine, osabi);
        assert_eq!(
            letters, r.flags,
            "{ctx}: section #{} flags {:#x}",
            s.index, s.sh_flags.value
        );
        all_flags |= s.sh_flags.value;
    }
    eprintln!("ok  sections {ctx}  ({} sections)", rows.len());
    all_flags
}

/// A retained section and an MBIND section: readelf names those flags only for some
/// `EI_OSABI` values (`R` for GNU and FreeBSD, `D` for those and System V, `o`
/// otherwise), so one object is checked with each value. Ubuntu's own binaries are
/// System V files with retained sections.
const OS_SPECIFIC_FLAGS: &str = "__attribute__((used, retain)) static int kept = 1;\n\
__asm__(\".section .mbind.data,\\\"awd\\\",%progbits,1\\n.byte 1\\n.previous\\n\");\n\
int f(void) { return kept; }\n";

#[test]
fn os_specific_section_flags_match_readelf() {
    use fg_loader::elf::consts::{SHF_GNU_MBIND, SHF_GNU_RETAIN};
    if !tool_available("readelf") || !tool_available("gcc") {
        eprintln!("note: readelf or gcc not found; skipped");
        return;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("oracle-osabi");
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join("flags.c");
    std::fs::write(&c, OS_SPECIFIC_FLAGS).unwrap();
    let object = dir.join("flags.o");
    let built = Command::new("gcc")
        .arg("-c")
        .arg(&c)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "gcc could not build the retain/mbind object (needs gcc 11 and binutils 2.36 or newer):\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let bytes = std::fs::read(&object).unwrap();
    // System V, GNU, FreeBSD, Solaris.
    for osabi in [0u8, 3, 9, 6] {
        let mut copy = bytes.clone();
        copy[fg_loader::elf::consts::EI_OSABI as usize] = osabi;
        let path = dir.join(format!("flags-osabi{osabi}.o"));
        std::fs::write(&path, &copy).unwrap();
        let all = check_sections(&path);
        // Without both flags the comparison would prove nothing.
        assert!(
            all & SHF_GNU_RETAIN != 0 && all & SHF_GNU_MBIND != 0,
            "{}: the object has no retained or no MBIND section",
            path.display()
        );
    }
}

/// One row of `readelf -W -s`.
#[derive(Debug)]
struct ReadelfSymbol {
    value: u64,
    size: u64,
    ty: String,
    bind: String,
    vis: String,
    ndx: String,
    name: String,
}

/// Symbol tables from `readelf -W -s`, keyed by table name (`.dynsym`, `.symtab`).
fn readelf_symbols(path: &Path) -> Vec<(String, Vec<ReadelfSymbol>)> {
    let out = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["-W", "-s"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tables: Vec<(String, Vec<ReadelfSymbol>)> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Symbol table '") {
            let name = rest.split('\'').next().unwrap_or("").to_string();
            tables.push((name, Vec::new()));
            continue;
        }
        let t = line.trim_start();
        let Some((num, rest)) = t.split_once(':') else {
            continue;
        };
        if num.parse::<u32>().is_err() {
            continue;
        }
        let Some((_, rows)) = tables.last_mut() else {
            continue;
        };
        let tok: Vec<&str> = rest.split_whitespace().collect();
        // value size type bind vis [extra st_other annotations in brackets] ndx name...
        let mut i = 5;
        while tok.get(i).is_some_and(|x| x.starts_with('[')) {
            while !tok[i].ends_with(']') {
                i += 1;
            }
            i += 1;
        }
        let size = if let Some(h) = tok[1].strip_prefix("0x") {
            u64::from_str_radix(h, 16).unwrap()
        } else {
            tok[1].parse().unwrap()
        };
        let mut name = tok.get(i + 1..).map(|n| n.join(" ")).unwrap_or_default();
        // Imports are printed as "printf@GLIBC_2.2.5 (2)": drop the version index.
        if name.ends_with(')')
            && let Some(p) = name.rfind(" (")
        {
            name.truncate(p);
        }
        rows.push(ReadelfSymbol {
            value: hex(tok[0]),
            size,
            ty: tok[2].to_string(),
            bind: tok[3].to_string(),
            vis: tok[4].to_string(),
            ndx: tok[i].to_string(),
            name,
        });
    }
    tables
}

#[test]
fn symbols_match_readelf() {
    use fg_loader::elf::consts::{st_bind_name, st_type_name, st_vis_name};
    if !tool_available("readelf") {
        return;
    }
    for path in inputs() {
        let bin = load_file(path);
        let elf = bin.elf().unwrap();
        let ctx = path.display();
        if elf.section_headers.is_empty() {
            continue; // readelf -s needs section headers; covered by the next test
        }
        let tables = readelf_symbols(path);
        let ours: Vec<(&str, &fg_loader::elf::ElfSymbolTable)> =
            [(".dynsym", &elf.dynsym), (".symtab", &elf.symtab)]
                .into_iter()
                .filter_map(|(n, t)| t.as_ref().map(|t| (n, t)))
                .collect();
        assert_eq!(ours.len(), tables.len(), "{ctx}: number of symbol tables");
        let neutral = |t: fg_loader::SymbolTable, i: u32| {
            bin.symbols
                .iter()
                .find(|s| s.table == t && s.index == i)
                .unwrap()
                .display_name()
        };
        for ((name, t), (rname, rows)) in ours.iter().zip(&tables) {
            assert_eq!(name, rname, "{ctx}: table order");
            assert_eq!(t.symbols.len(), rows.len(), "{ctx}: {name} entry count");
            for (s, r) in t.symbols.iter().zip(rows) {
                let at = format!("{ctx}: {name} #{}", s.index);
                assert_eq!(
                    (s.st_value.value, s.st_size.value),
                    (r.value, r.size),
                    "{at} value/size"
                );
                assert_eq!(st_type_name(s.st_type()), r.ty, "{at} type");
                assert_eq!(st_bind_name(s.st_bind()), r.bind, "{at} bind");
                assert_eq!(st_vis_name(s.st_visibility()), r.vis, "{at} visibility");
                assert_eq!(s.ndx_display(), r.ndx, "{at} section index");
                assert_eq!(neutral(t.table, s.index), r.name, "{at} name with version");
            }
        }
        eprintln!(
            "ok  symbols  {ctx}  ({})",
            tables
                .iter()
                .map(|(n, r)| format!("{n} {}", r.len()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

#[test]
fn dynamic_symbols_survive_section_header_removal() {
    let (Some(original), Some(noshdr)) = (variant("buf_default"), variant("noshdr")) else {
        eprintln!(
            "note: noshdr variant unavailable (needs objcopy --strip-section-headers); skipped"
        );
        return;
    };
    let a = load_file(original);
    let b = load_file(noshdr);
    assert!(
        b.elf().unwrap().section_headers.is_empty(),
        "section headers really removed"
    );
    let dynamic = |bin: &LoadedBinary| -> Vec<String> {
        bin.symbols
            .iter()
            .filter(|s| s.table == fg_loader::SymbolTable::Dynamic)
            .map(|s| s.display_name())
            .collect()
    };
    assert_eq!(
        dynamic(&a),
        dynamic(&b),
        "same dynamic symbols, found without section headers"
    );
    assert_eq!(a.imports().count(), b.imports().count());
    assert_eq!(
        b.mitigations.canary.verdict,
        Verdict::Enabled,
        "canary still detected"
    );
    // `.eh_frame` is found through PT_GNU_EH_FRAME, as the run time finds it.
    let unwind = |bin: &LoadedBinary| -> Vec<(u64, Option<u64>)> {
        bin.seeds
            .iter()
            .filter(|s| s.kind == fg_loader::SeedKind::UnwindTable)
            .map(|s| (s.va.0, s.end.map(|e| e.0)))
            .collect()
    };
    assert!(!unwind(&a).is_empty());
    assert_eq!(unwind(&a), unwind(&b), "same FDEs without section headers");
    eprintln!(
        "ok  noshdr   {} dynamic symbols recovered through the dynamic segment, {} FDEs",
        dynamic(&b).len(),
        unwind(&b).len()
    );
}

/// One row of `readelf -W -r`: (r_offset, r_info, type, symbol name, addend).
type RelocRow = (u64, u64, String, Option<String>, Option<i64>);

/// One relocation section from `readelf -W -r`.
#[derive(Debug, Default)]
struct ReadelfRelocs {
    name: String,
    offset: u64,
    rows: Vec<RelocRow>,
    /// Decoded addresses (RELR sections only).
    relr: Vec<u64>,
    is_relr: bool,
}

fn signed_hex(s: &str) -> i64 {
    match s.strip_prefix('-') {
        Some(h) => -(hex(h) as i64),
        None => hex(s) as i64,
    }
}

fn readelf_relocs(path: &Path) -> Vec<ReadelfRelocs> {
    let out = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["-W", "-r"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut secs: Vec<ReadelfRelocs> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Relocation section '") {
            let (name, rest) = rest.split_once('\'').unwrap();
            let off = rest.split_whitespace().nth(2).unwrap();
            secs.push(ReadelfRelocs {
                name: name.to_string(),
                offset: hex(off),
                is_relr: rest.contains("which relocate"),
                ..ReadelfRelocs::default()
            });
            continue;
        }
        let Some(sec) = secs.last_mut() else { continue };
        let tok: Vec<&str> = line.split_whitespace().collect();
        if tok.is_empty() || tok[0] == "Offset" || tok[0] == "Index:" {
            continue;
        }
        if sec.is_relr {
            let addr = if tok[0].ends_with(':') {
                tok.get(2)
            } else {
                tok.first()
            };
            if let Some(a) = addr.filter(|a| u64::from_str_radix(a, 16).is_ok()) {
                sec.relr.push(hex(a));
            }
            continue;
        }
        if tok.len() < 3 || u64::from_str_radix(tok[0], 16).is_err() {
            continue;
        }
        let rest = &tok[3..];
        let (symbol, addend) = match rest.len() {
            0 => (None, None),
            1 => (None, Some(signed_hex(rest[0]))),
            2 => (Some(rest[1].to_string()), None),
            _ => {
                let a = signed_hex(rest[rest.len() - 1]);
                let a = if rest[rest.len() - 2] == "-" { -a } else { a };
                (Some(rest[1..rest.len() - 2].join(" ")), Some(a))
            }
        };
        sec.rows
            .push((hex(tok[0]), hex(tok[1]), tok[2].to_string(), symbol, addend));
    }
    secs
}

#[test]
fn relocations_match_readelf() {
    if !tool_available("readelf") {
        return;
    }
    for path in inputs() {
        let bin = load_file(path);
        let elf = bin.elf().unwrap();
        let ctx = path.display();
        if elf.section_headers.is_empty() {
            continue; // readelf -r lists by section; covered by the no-section-header test
        }
        let secs = readelf_relocs(path);
        let mut checked = 0;
        for sec in &secs {
            let shdr = elf
                .section_headers
                .iter()
                .find(|s| s.sh_offset.value == sec.offset && s.name_str() == sec.name)
                .unwrap_or_else(|| panic!("{ctx}: no section header for {}", sec.name));
            if sec.is_relr {
                let t = elf
                    .relocations
                    .iter()
                    .find(|t| t.name == sec.name)
                    .unwrap_or_else(|| panic!("{ctx}: RELR table {} not read", sec.name));
                let ours: Vec<u64> = t.entries.iter().map(|e| e.r_offset.value).collect();
                assert_eq!(ours, sec.relr, "{ctx}: {} decoded addresses", sec.name);
                checked += ours.len();
                continue;
            }
            let ent = match (shdr.sh_type.value, bin.bitness) {
                (4, fg_core::Bitness::Bits64) => 24,
                (4, _) => 12,
                (_, fg_core::Bitness::Bits64) => 16,
                _ => 8,
            };
            for (i, (off, info, ty, symbol, addend)) in sec.rows.iter().enumerate() {
                let at = sec.offset + i as u64 * ent;
                let here = format!("{ctx}: {} #{i}", sec.name);
                let raw = elf
                    .relocations
                    .iter()
                    .flat_map(|t| &t.entries)
                    .find(|e| e.span.offset.0 == at)
                    .unwrap_or_else(|| panic!("{here}: entry at {at:#x} not read"));
                let neutral = bin
                    .relocations
                    .iter()
                    .find(|r| r.defined_by.offset.0 == at)
                    .unwrap();
                assert_eq!(raw.r_offset.value, *off, "{here} offset");
                assert_eq!(raw.r_info.as_ref().unwrap().value, *info, "{here} info");
                if let Some(name) = neutral.type_name {
                    assert_eq!(name, ty, "{here} type");
                }
                if let Some(sym) = symbol {
                    assert_eq!(
                        neutral.symbol_name.as_deref(),
                        Some(sym.as_str()),
                        "{here} symbol"
                    );
                }
                if let Some(a) = addend {
                    assert_eq!(neutral.addend, Some(*a), "{here} addend");
                }
                checked += 1;
            }
        }
        eprintln!(
            "ok  relocs   {ctx}  ({} sections, {checked} relocations)",
            secs.len()
        );
    }
}

#[test]
fn relocations_survive_section_header_removal() {
    let (Some(original), Some(noshdr)) = (variant("buf_default"), variant("noshdr")) else {
        return;
    };
    let key = |b: &LoadedBinary| -> Vec<(u64, u32, Option<String>, Option<i64>)> {
        b.relocations
            .iter()
            .map(|r| (r.offset, r.r_type, r.symbol_name.clone(), r.addend))
            .collect()
    };
    let (a, b) = (load_file(original), load_file(noshdr));
    assert!(!a.relocations.is_empty());
    assert_eq!(key(&a), key(&b), "same relocations without section headers");
    assert_eq!(a.build_id, b.build_id, "build ID found through PT_NOTE");
    assert_eq!(a.mitigations.cfi.verdict, b.mitigations.cfi.verdict);
    eprintln!(
        "ok  noshdr   {} relocations and the build ID recovered through the segments",
        b.relocations.len()
    );
}

/// Notes from `readelf -W -n` as comparable strings.
fn readelf_notes(path: &Path) -> Vec<String> {
    let out = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["-W", "-n"])
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut notes = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        let head: Vec<&str> = parts[0].split_whitespace().collect();
        if head.len() < 2 || !head[head.len() - 1].starts_with("0x") || parts.len() < 2 {
            continue;
        }
        let owner = head[..head.len() - 1].join(" ");
        let size = head[head.len() - 1];
        let ty = parts[1].trim();
        let payload = parts.get(2).map_or("", |p| p.trim());
        notes.push(note_key(&owner, size, ty, payload));
    }
    notes.sort();
    notes
}

/// Only GNU notes of the types Fulgurite decodes are compared in full.
fn note_key(owner: &str, size: &str, ty: &str, payload: &str) -> String {
    let decoded = owner == "GNU"
        && [
            "NT_GNU_BUILD_ID",
            "NT_GNU_ABI_TAG",
            "NT_GNU_PROPERTY_TYPE_0",
        ]
        .iter()
        .any(|t| ty.starts_with(t));
    if decoded {
        format!("{owner}|{size}|{ty}|{}", payload.trim())
    } else {
        format!("{owner}|{size}")
    }
}

#[test]
fn notes_match_readelf() {
    use fg_loader::elf::NoteContent;
    if !tool_available("readelf") {
        return;
    }
    for path in inputs() {
        let bin = load_file(path);
        let elf = bin.elf().unwrap();
        let ctx = path.display();
        let mut ours: Vec<String> = elf
            .notes
            .iter()
            .map(|n| {
                let ty = match n.owner.value.as_str() {
                    "GNU" => fg_loader::elf::consts::gnu_note_type_name(n.n_type.value)
                        .unwrap_or("")
                        .to_string(),
                    _ => String::new(),
                };
                let payload = match &n.content {
                    NoteContent::BuildId(id) => format!("Build ID: {id}"),
                    NoteContent::AbiTag { os, version } => format!("OS: {os}, ABI: {version}"),
                    NoteContent::Properties(p) => format!(
                        "Properties: {}",
                        p.iter()
                            .map(|p| p.text.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    _ => String::new(),
                };
                note_key(
                    &n.owner.value,
                    &format!("{:#010x}", n.desc.len),
                    &ty,
                    &payload,
                )
            })
            .collect();
        ours.sort();
        assert_eq!(ours, readelf_notes(path), "{ctx}: notes");
        eprintln!("ok  notes    {ctx}  ({} notes)", ours.len());
    }
}

/// Code seeds from `DT_INIT`, `DT_FINI` and the init/fini arrays land exactly on
/// function symbols (`frame_dummy`, `__do_global_dtors_aux`, `_init`, ...) in
/// every binary that still has its symbol table, and the entry seed is the entry.
/// `.eh_frame` seeds land on function symbols except in three known cases.
#[test]
fn elf_seeds_are_function_starts() {
    use fg_loader::{SeedKind, SymbolKind, SymbolTable};
    let mut arrays = 0;
    // FDE seeds at a function symbol, covering a PLT section, padding before a function.
    // ... and mid-frame FDEs at `.cold` parts.
    // ... and signal trampolines' FDEs one byte before the trampoline.
    let mut unwind = [0u32; 5];
    for path in inputs() {
        let b = load_file(path);
        let ctx = path.display();
        if let Some(e) = &b.entry {
            assert!(
                b.seeds
                    .iter()
                    .any(|s| s.kind == SeedKind::Entry && s.va == e.value),
                "{ctx}: entry seed"
            );
        }
        let funcs: std::collections::HashSet<u64> = b
            .symbols
            .iter()
            .filter(|s| {
                s.table == SymbolTable::Static && s.kind == SymbolKind::Function && s.defined
            })
            .map(|s| s.va.0)
            .collect();
        if funcs.is_empty() {
            continue;
        }
        // An FDE describes a code range, not always a function. Every FDE seed
        // that is not at a function symbol must be one of the known cases.
        let plt: Vec<(u64, u64)> = b
            .sections
            .iter()
            .filter(|s| matches!(s.name.as_str(), ".plt" | ".plt.sec" | ".plt.got"))
            .filter_map(|s| s.va.map(|v| (v.0, v.0 + s.size)))
            .collect();
        // An FDE that starts mid-frame is a compiler-split part (`foo.cold`),
        // or the linker's FDE for a PLT section (PLT0 pushes before jumping).
        for s in b
            .seeds
            .iter()
            .filter(|s| s.kind == SeedKind::UnwindFragment)
        {
            let (va, end) = (s.va.0, s.end.expect("FDE seeds have an end").0);
            assert!(
                plt.contains(&(va, end))
                    || b.symbols
                        .iter()
                        .any(|y| y.va == s.va && y.name.contains(".cold")),
                "{ctx}: mid-frame FDE {} is neither a .cold part nor a PLT section",
                s.va
            );
            unwind[3] += 1;
        }
        // A signal trampoline's FDE starts one byte before it (x86 glibc).
        for s in b.seeds.iter().filter(|s| s.kind == SeedKind::UnwindSignal) {
            assert!(funcs.contains(&(s.va.0 + 1)), "{ctx}: signal FDE {}", s.va);
            unwind[4] += 1;
        }
        for s in b.seeds.iter().filter(|s| s.kind == SeedKind::UnwindTable) {
            let (va, end) = (s.va.0, s.end.expect("FDE seeds have an end").0);
            if funcs.contains(&va) {
                unwind[0] += 1;
            } else if plt.contains(&(va, end)) {
                // The linker's FDE for a whole PLT section.
                unwind[1] += 1;
            } else if funcs.iter().any(|&f| va < f && f < end && f - va < 16) {
                // Leading bytes before the function: alignment padding inside the
                // CFI region of hand-written assembly.
                unwind[2] += 1;
            } else {
                panic!(
                    "{ctx}: FDE seed {va:#x}..{end:#x} is neither a function, a PLT section nor padding before a function"
                );
            }
        }
        for s in b.seeds.iter().filter(|s| {
            !matches!(
                s.kind,
                SeedKind::Entry
                    | SeedKind::UnwindTable
                    | SeedKind::UnwindFragment
                    | SeedKind::UnwindSignal
            )
        }) {
            assert!(
                funcs.contains(&s.va.0),
                "{ctx}: {:?} seed {} is not a function start",
                s.kind,
                s.va
            );
            arrays += 1;
        }
    }
    eprintln!("ELF init/fini seeds checked against symbols: {arrays}");
    eprintln!(
        "ELF .eh_frame seeds: {} at functions, {} PLT sections, {} padding before a function, {} .cold parts, {} signal trampolines",
        unwind[0], unwind[1], unwind[2], unwind[3], unwind[4]
    );
    assert!(unwind[0] > 0, "the fixtures have .eh_frame");
    if tool_available("gcc") {
        assert!(arrays > 0, "gcc-built variants have init/fini arrays");
    }
}
