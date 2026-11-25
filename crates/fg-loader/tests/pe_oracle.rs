// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Cross-checks the PE loader against independent implementations:
//!
//! * `llvm-readobj` (LLVM's COFF dumper) for every parsed value: file, optional
//!   and DOS headers, data directories, sections, imports, delay imports, exports,
//!   base relocations, TLS, the load configuration with its guard tables, the
//!   debug directory, x64 and ARM64 unwind data, COFF symbols and resources.
//! * `objdump -p` (GNU binutils, `pei-*` targets) for headers and imports, so the
//!   check also runs where LLVM is not installed.
//!
//! Inputs: PE files built here with any installed MinGW toolchain (llvm-mingw:
//! x86-64, i686, ARM64, ARMv7; GNU MinGW: x86-64, i686), Go's PE test data, and
//! the PE files a Linux system commonly has (UEFI boot loaders, MinGW DLLs).
//! Every tool is optional: a missing one skips its part with a note.

use fg_loader::pe::{DebugContent, PeInfo, ResourceName, UnwindInfo};
use fg_loader::{LoadOptions, LoadedBinary, SymbolTable, load};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

// ---------------------------------------------------------------- fixtures

const HELLO_C: &str = r#"
#include <windows.h>
#include <stdio.h>
#include <string.h>
__declspec(dllexport) int exported_add(int a, int b) { return a + b; }
static void NTAPI tls_cb(PVOID h, DWORD reason, PVOID r) { (void)h; (void)r; (void)reason; }
__attribute__((section(".CRT$XLB"), used)) PIMAGE_TLS_CALLBACK p_tls_cb = tls_cb;
int vuln(const char *s) { char buf[64]; strcpy(buf, s); return buf[0]; }
int main(int argc, char **argv) {
  printf("hello %d\n", exported_add(argc, 2));
  MessageBoxA(NULL, "hi", "t", 0);
  if (argc > 1) return vuln(argv[1]);
  return (int)GetTickCount();
}
"#;

const LIB_C: &str = r#"
int lib_counter = 3;
int lib_add(int a, int b) { return a + b + lib_counter; }
int lib_secret(int a) { return a * 7; }
int zeta(void) { return 1; }
"#;

const LIB_DEF: &str = "LIBRARY fglib.dll\nEXPORTS\n  zeta\n  lib_add\n  lib_secret @7 NONAME\n  lib_counter DATA\n  lib_sleep = KERNEL32.Sleep\n";

const USE_C: &str = r#"
extern int lib_add(int, int);
extern int lib_secret(int);
extern __declspec(dllimport) int lib_counter;
int main(void) { return lib_add(1, 2) + lib_secret(3) + lib_counter; }
"#;

const RES_RC: &str = r#"
1 VERSIONINFO
FILEVERSION 1,2,3,4
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "FileDescription", "Fulgurite test\0"
    END
  END
END
2 RCDATA { "payload bytes" }
PAYLOAD MYTYPE { "named resource" }
"#;

/// A MinGW cross toolchain: the compiler for one target triple.
struct Toolchain {
    /// e.g. `/opt/llvm-mingw/llvm-mingw-ucrt/bin/x86_64-w64-mingw32-clang`.
    cc: PathBuf,
    /// llvm-mingw (lld) rather than GNU (ld.bfd): accepts lld-only options.
    llvm: bool,
    triple: &'static str,
}

impl Toolchain {
    fn tool(&self, name: &str) -> PathBuf {
        self.cc.with_file_name(format!("{}-{name}", self.triple))
    }
}

fn toolchains() -> Vec<Toolchain> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/opt/llvm-mingw") {
        dirs.extend(rd.flatten().map(|e| e.path().join("bin")));
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    let mut out: Vec<Toolchain> = Vec::new();
    for triple in [
        "x86_64-w64-mingw32",
        "i686-w64-mingw32",
        "aarch64-w64-mingw32",
        "armv7-w64-mingw32",
    ] {
        let found = dirs.iter().find_map(|d| {
            let clang = d.join(format!("{triple}-clang"));
            let gcc = d.join(format!("{triple}-gcc"));
            if clang.is_file() {
                Some(Toolchain {
                    cc: clang,
                    llvm: true,
                    triple,
                })
            } else if gcc.is_file() {
                // llvm-mingw also ships a `-gcc` wrapper; treat it as llvm if lld is beside it.
                let llvm = d.join("ld.lld").is_file() || d.join("lld").is_file();
                Some(Toolchain {
                    cc: gcc,
                    llvm,
                    triple,
                })
            } else {
                None
            }
        });
        out.extend(found);
    }
    out
}

fn run_ok(cmd: &mut Command) -> bool {
    cmd.output().is_ok_and(|o| o.status.success())
}

fn build_fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pe-oracle");
    let _ = std::fs::create_dir_all(&dir);
    let write = |name: &str, text: &str| {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let hello = write("hello.c", HELLO_C);
    let lib_c = write("lib.c", LIB_C);
    let lib_def = write("lib.def", LIB_DEF);
    let use_c = write("use.c", USE_C);
    let rc = write("res.rc", RES_RC);
    let mut out = Vec::new();
    let tcs = toolchains();
    if tcs.is_empty() {
        eprintln!("note: no MinGW toolchain found; built PE fixtures skipped");
    }
    for tc in &tcs {
        let arch = tc.triple.split('-').next().unwrap_or("x");
        let mut variant = |name: String, args: &[&str]| {
            let exe = dir.join(&name);
            let mut cmd = Command::new(&tc.cc);
            cmd.args(args).arg("-o").arg(&exe);
            if run_ok(&mut cmd) {
                out.push(exe);
            } else {
                eprintln!("note: could not build {name} with {}", tc.cc.display());
            }
        };
        let h = hello.to_str().unwrap();
        variant(
            format!("hello-{arch}.exe"),
            &["-O1", "-fstack-protector-strong", h, "-luser32"],
        );
        variant(
            format!("hello-{arch}-stripped.exe"),
            &["-O1", "-s", h, "-luser32"],
        );
        variant(
            format!("hello-{arch}-fixed.exe"),
            &[
                h,
                "-luser32",
                "-Wl,--disable-dynamicbase,--disable-nxcompat",
            ],
        );
        if tc.llvm {
            variant(
                format!("hello-{arch}-cfg.exe"),
                &[
                    "-O1",
                    "-mguard=cf",
                    h,
                    "-luser32",
                    "-Wl,--delayload=user32.dll",
                ],
            );
        }
        // A DLL with every export form, and programs importing from it.
        let dll = dir.join(format!("fglib-{arch}.dll"));
        let implib = dir.join(format!("libfglib-{arch}.a"));
        let mut cmd = Command::new(&tc.cc);
        cmd.arg("-shared")
            .arg("-o")
            .arg(&dll)
            .arg(&lib_c)
            .arg(&lib_def)
            .arg(format!("-Wl,--out-implib,{}", implib.display()));
        if !run_ok(&mut cmd) {
            eprintln!("note: could not build {}", dll.display());
            continue;
        }
        out.push(dll);
        let res_o = dir.join(format!("res-{arch}.o"));
        let have_res = run_ok(
            Command::new(tc.tool("windres"))
                .arg(&rc)
                .args(["-O", "coff", "-o"])
                .arg(&res_o),
        );
        let lib_dir = format!("-L{}", dir.display());
        let lib = format!("-lfglib-{arch}");
        let mut args = vec![use_c.to_str().unwrap(), &lib_dir, &lib];
        let res_s = res_o.to_string_lossy().to_string();
        if have_res {
            args.push(&res_s);
        }
        let mut variant = |name: String, args: &[&str]| {
            let exe = dir.join(&name);
            let mut cmd = Command::new(&tc.cc);
            cmd.args(args).arg("-o").arg(&exe);
            if run_ok(&mut cmd) {
                out.push(exe);
            } else {
                eprintln!("note: could not build {name}");
            }
        };
        variant(format!("use-{arch}.exe"), &args);
        if tc.llvm {
            let mut a = args.clone();
            a.extend(["-Wl,--dependent-load-flag=0x800", "-Wl,-Xlink=-cetcompat"]);
            variant(format!("use-{arch}-hardened.exe"), &a);
        }
    }
    out
}

fn system_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut roots = vec![
        PathBuf::from("/usr/share/limine"),
        PathBuf::from("/usr/lib/systemd/boot/efi"),
        PathBuf::from("/usr/lib/vmware"),
        PathBuf::from("/usr/lib/shim"),
        PathBuf::from("/usr/lib/grub/x86_64-efi-signed"),
    ];
    if let Ok(o) = Command::new("go").args(["env", "GOROOT"]).output() {
        let root = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !root.is_empty() {
            roots.push(Path::new(&root).join("src/debug/pe/testdata"));
        }
    }
    if let Ok(rd) = std::fs::read_dir("/opt/llvm-mingw") {
        for e in rd.flatten() {
            for t in ["x86_64", "i686", "aarch64", "armv7"] {
                roots.push(e.path().join(format!("{t}-w64-mingw32/bin")));
            }
        }
    }
    let mut stack = roots;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if std::fs::read(&p).is_ok_and(|b| b.starts_with(b"MZ") && b.len() > 0x100) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn inputs() -> &'static [PathBuf] {
    static INPUTS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    INPUTS.get_or_init(|| {
        let mut v = build_fixtures();
        v.extend(system_files());
        eprintln!("PE oracle corpus: {} files", v.len());
        v
    })
}

fn load_file(path: &Path) -> Option<LoadedBinary> {
    let bytes = std::fs::read(path).ok()?;
    match load(&bytes, &LoadOptions::default()) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("note: {} not loaded: {e}", path.display());
            None
        }
    }
}

// ---------------------------------------------------------------- llvm-readobj

/// Asserts two lists are equal, reporting only the first difference.
fn same_list<T: PartialEq + std::fmt::Debug>(theirs: &[T], ours: &[T], ctx: &str) {
    if let Some(i) = (0..theirs.len().min(ours.len())).find(|&i| theirs[i] != ours[i]) {
        panic!(
            "{ctx}: entry {i} differs: oracle {:?}, ours {:?}",
            theirs[i], ours[i]
        );
    }
    assert_eq!(theirs.len(), ours.len(), "{ctx}: count");
}

fn llvm_readobj() -> Option<PathBuf> {
    static TOOL: OnceLock<Option<PathBuf>> = OnceLock::new();
    TOOL.get_or_init(|| {
        if run_ok(Command::new("llvm-readobj").arg("--version")) {
            return Some(PathBuf::from("llvm-readobj"));
        }
        // Debian/Ubuntu install versioned copies.
        let mut found: Vec<PathBuf> = std::fs::read_dir("/usr/lib")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path().join("bin/llvm-readobj"))
            .filter(|p| p.is_file())
            .collect();
        found.sort();
        found.pop()
    })
    .clone()
}

/// One line of `llvm-readobj` output, with its nested block if it opens one.
#[derive(Debug, Default)]
struct Node {
    key: String,
    value: String,
    children: Vec<Node>,
}

impl Node {
    fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.key == key)
    }
    fn get(&self, key: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.key == key)
    }
    fn val(&self, key: &str) -> &str {
        self.get(key).map_or("", |n| n.value.as_str())
    }
    fn num(&self, key: &str) -> u64 {
        num(self.val(key)).unwrap_or_else(|| panic!("no number for {key:?} in {:?}", self.key))
    }
}

/// `0x1A`, `26`, `2026-10-10 11:11:05 (0x6ACA1D49)`, `IMAGE_FILE_MACHINE_AMD64 (0x8664)`, `(0x22)`.
fn num(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = match (s.rfind('('), s.ends_with(')')) {
        (Some(i), true) => &s[i + 1..s.len() - 1],
        _ => s,
    };
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(d) = s.strip_prefix('-') {
        d.parse::<i64>().ok().map(|v| (-v) as u64)
    } else {
        s.parse().ok()
    }
}

fn parse_readobj(text: &str) -> Node {
    let mut stack = vec![Node::default()];
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "}" | "]" | ")") {
            if stack.len() > 1 {
                let n = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(n);
            }
            continue;
        }
        // `Key [ (0x22)`: a flag block carrying the raw value.
        let (head, flag_value) = match line.find(" [ (") {
            Some(i) if line.ends_with(')') => (&line[..i + 2], Some(&line[i + 3..])),
            _ => (line, None),
        };
        let opens = flag_value.is_some()
            || head.ends_with(" {")
            || head.ends_with(" [")
            || head.ends_with(" (")
            || matches!(head, "{" | "[" | "(");
        let body = if opens {
            head[..head.len() - 1].trim_end()
        } else {
            head
        };
        let (key, value) = match body.split_once(": ") {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => match body.strip_suffix(':') {
                Some(k) => (k.to_string(), String::new()),
                None => (body.to_string(), String::new()),
            },
        };
        let value = flag_value.map_or(value, str::to_string);
        let node = Node {
            key,
            value,
            children: Vec::new(),
        };
        if opens {
            stack.push(node);
        } else {
            stack.last_mut().unwrap().children.push(node);
        }
    }
    while stack.len() > 1 {
        let n = stack.pop().unwrap();
        stack.last_mut().unwrap().children.push(n);
    }
    stack.pop().unwrap()
}

fn readobj(tool: &Path, path: &Path, args: &[&str]) -> Node {
    let out = Command::new(tool)
        .args(args)
        .arg(path)
        .output()
        .expect("llvm-readobj runs");
    parse_readobj(&String::from_utf8_lossy(&out.stdout))
}

fn x64_reg(n: u8) -> String {
    const R: [&str; 16] = [
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15",
    ];
    R[usize::from(n & 15)].to_string()
}

#[test]
fn matches_llvm_readobj() {
    let Some(tool) = llvm_readobj() else {
        eprintln!("note: llvm-readobj not found, oracle skipped");
        return;
    };
    let mut checked = 0;
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for path in inputs() {
        let Some(b) = load_file(path) else { continue };
        let pe = b.pe().expect("PE metadata");
        let ctx = path.display().to_string();
        let r = readobj(
            &tool,
            path,
            &[
                "--file-headers",
                "--sections",
                "--coff-imports",
                "--coff-exports",
                "--coff-basereloc",
                "--coff-tls-directory",
                "--coff-load-config",
                "--coff-debug-directory",
            ],
        );
        if r.get("ImageFileHeader").is_none() {
            eprintln!("note: llvm-readobj could not read {ctx}");
            continue;
        }
        if pe.sections.iter().any(|s| {
            u64::from(s.pointer_to_raw_data.value) + u64::from(s.size_of_raw_data.value)
                > b.file_size
        }) {
            eprintln!("note: {ctx} is truncated; only headers compared");
            headers(&r, pe, &ctx);
            continue;
        }
        headers(&r, pe, &ctx);
        sections(&r, pe, &ctx);
        imports(&r, pe, &ctx);
        exports(&r, &b, &ctx);
        base_relocs(&r, &b, &ctx);
        tls(&r, pe, &ctx);
        load_config(&r, pe, &ctx);
        debug(&r, pe, &ctx);
        let u = readobj(&tool, path, &["--unwind"]);
        unwind(&u, pe, &ctx);
        let s = readobj(&tool, path, &["--symbols"]);
        symbols(&s, &b, &ctx);
        let res = readobj(&tool, path, &["--coff-resources"]);
        resources(&res, pe, &ctx);
        checked += 1;
        let lc = pe.load_config.as_ref();
        for (k, n) in [
            ("sections", pe.sections.len()),
            (
                "imports",
                pe.imports
                    .iter()
                    .chain(&pe.delay_imports)
                    .map(|d| d.entries.len())
                    .sum(),
            ),
            (
                "exports",
                pe.exports.as_ref().map_or(0, |x| x.entries.len()),
            ),
            (
                "base relocations",
                b.relocations
                    .iter()
                    .filter(|r| r.table == "base relocations")
                    .count(),
            ),
            ("exception entries", pe.exception.len()),
            (
                "x64 unwind codes",
                pe.exception
                    .iter()
                    .map(|f| match &f.info {
                        Some(UnwindInfo::X64(x)) => x.codes.len(),
                        _ => 0,
                    })
                    .sum(),
            ),
            ("load config fields", lc.map_or(0, |l| l.fields.len())),
            ("CFG targets", lc.map_or(0, |l| l.guard_cf_functions.len())),
            ("debug entries", pe.debug.len()),
            ("COFF symbols", pe.coff_symbols.len()),
            ("resources", pe.resources.len()),
        ] {
            *totals.entry(k).or_insert(0) += n;
        }
        eprintln!("ok  llvm-readobj  {ctx}");
    }
    eprintln!("llvm-readobj oracle: {checked} files fully compared; {totals:?}");
}

fn headers(r: &Node, pe: &PeInfo, ctx: &str) {
    let fh = r.get("ImageFileHeader").unwrap();
    let f = &pe.file_header;
    assert_eq!(
        fh.num("Machine"),
        u64::from(f.machine.value),
        "{ctx}: Machine"
    );
    assert_eq!(
        fh.num("SectionCount"),
        u64::from(f.number_of_sections.value),
        "{ctx}"
    );
    assert_eq!(
        fh.num("TimeDateStamp"),
        u64::from(f.time_date_stamp.value),
        "{ctx}"
    );
    assert_eq!(
        fh.num("PointerToSymbolTable"),
        u64::from(f.pointer_to_symbol_table.value),
        "{ctx}"
    );
    // LLVM reports 0 symbols when there is no table, whatever the count field says.
    if f.pointer_to_symbol_table.value != 0 {
        assert_eq!(
            fh.num("SymbolCount"),
            u64::from(f.number_of_symbols.value),
            "{ctx}"
        );
    }
    assert_eq!(
        fh.num("OptionalHeaderSize"),
        u64::from(f.size_of_optional_header.value),
        "{ctx}"
    );
    assert_eq!(
        fh.num("Characteristics"),
        u64::from(f.characteristics.value),
        "{ctx}"
    );

    let oh = r.get("ImageOptionalHeader").unwrap();
    let o = &pe.optional;
    let pairs: [(&str, u64); 28] = [
        ("Magic", o.magic.value.into()),
        ("MajorLinkerVersion", o.major_linker_version.value.into()),
        ("MinorLinkerVersion", o.minor_linker_version.value.into()),
        ("SizeOfCode", o.size_of_code.value.into()),
        (
            "SizeOfInitializedData",
            o.size_of_initialized_data.value.into(),
        ),
        (
            "SizeOfUninitializedData",
            o.size_of_uninitialized_data.value.into(),
        ),
        ("AddressOfEntryPoint", o.address_of_entry_point.value.into()),
        ("BaseOfCode", o.base_of_code.value.into()),
        ("ImageBase", o.image_base.value),
        ("SectionAlignment", o.section_alignment.value.into()),
        ("FileAlignment", o.file_alignment.value.into()),
        (
            "MajorOperatingSystemVersion",
            o.major_operating_system_version.value.into(),
        ),
        (
            "MinorOperatingSystemVersion",
            o.minor_operating_system_version.value.into(),
        ),
        ("MajorImageVersion", o.major_image_version.value.into()),
        ("MinorImageVersion", o.minor_image_version.value.into()),
        (
            "MajorSubsystemVersion",
            o.major_subsystem_version.value.into(),
        ),
        (
            "MinorSubsystemVersion",
            o.minor_subsystem_version.value.into(),
        ),
        ("SizeOfImage", o.size_of_image.value.into()),
        ("SizeOfHeaders", o.size_of_headers.value.into()),
        ("CheckSum", o.checksum.value.into()),
        ("Subsystem", o.subsystem.value.into()),
        ("Characteristics", o.dll_characteristics.value.into()),
        ("SizeOfStackReserve", o.size_of_stack_reserve.value),
        ("SizeOfStackCommit", o.size_of_stack_commit.value),
        ("SizeOfHeapReserve", o.size_of_heap_reserve.value),
        ("SizeOfHeapCommit", o.size_of_heap_commit.value),
        ("NumberOfRvaAndSize", o.number_of_rva_and_sizes.value.into()),
        (
            "BaseOfData",
            o.base_of_data.as_ref().map_or(0, |b| b.value.into()),
        ),
    ];
    for (k, ours) in pairs {
        if k == "BaseOfData" && o.base_of_data.is_none() {
            continue;
        }
        assert_eq!(oh.num(k), ours, "{ctx}: optional header {k}");
    }
    let dd = oh.get("DataDirectory").unwrap();
    for d in &o.data_directories {
        let names = [
            "ExportTable",
            "ImportTable",
            "ResourceTable",
            "ExceptionTable",
            "CertificateTable",
            "BaseRelocationTable",
            "Debug",
            "Architecture",
            "GlobalPtr",
            "TLSTable",
            "LoadConfigTable",
            "BoundImport",
            "IAT",
            "DelayImportDescriptor",
            "CLRRuntimeHeader",
            "Reserved",
        ];
        let n = names[usize::from(d.index)];
        assert_eq!(
            dd.num(&format!("{n}RVA")),
            u64::from(d.rva.value),
            "{ctx}: {n}RVA"
        );
        assert_eq!(
            dd.num(&format!("{n}Size")),
            u64::from(d.size.value),
            "{ctx}: {n}Size"
        );
    }
    let dos = r.get("DOSHeader").unwrap();
    assert_eq!(
        dos.num("AddressOfNewExeHeader"),
        u64::from(pe.dos.e_lfanew.value),
        "{ctx}"
    );
    assert_eq!(
        dos.num("UsedBytesInTheLastPage"),
        u64::from(pe.dos.e_cblp.value),
        "{ctx}"
    );
    assert_eq!(
        dos.num("HeaderSizeInParagraphs"),
        u64::from(pe.dos.e_cparhdr.value),
        "{ctx}"
    );
}

fn sections(r: &Node, pe: &PeInfo, ctx: &str) {
    let list: Vec<&Node> = r.get("Sections").unwrap().all("Section").collect();
    assert_eq!(list.len(), pe.sections.len(), "{ctx}: section count");
    for (n, s) in list.iter().zip(&pe.sections) {
        let name = n.val("Name");
        let name = name.rsplit_once(" (").map_or(name, |(a, _)| a);
        assert_eq!(name, s.name, "{ctx}: section name");
        assert_eq!(
            n.num("VirtualSize"),
            u64::from(s.virtual_size.value),
            "{ctx}: {name}"
        );
        assert_eq!(
            n.num("VirtualAddress"),
            u64::from(s.virtual_address.value),
            "{ctx}: {name}"
        );
        assert_eq!(
            n.num("RawDataSize"),
            u64::from(s.size_of_raw_data.value),
            "{ctx}: {name}"
        );
        assert_eq!(
            n.num("PointerToRawData"),
            u64::from(s.pointer_to_raw_data.value),
            "{ctx}: {name}"
        );
        assert_eq!(
            n.num("Characteristics"),
            u64::from(s.characteristics.value),
            "{ctx}: {name}"
        );
    }
}

/// `name (hint)` or ` (ordinal)` -> (name, number).
fn symbol_and_number(v: &str) -> (String, u64) {
    let (n, h) = v.rsplit_once(" (").unwrap_or((v, "0)"));
    (
        n.trim().to_string(),
        num(h.trim_end_matches(')')).unwrap_or(0),
    )
}

fn imports(r: &Node, pe: &PeInfo, ctx: &str) {
    let list: Vec<&Node> = r.all("Import").collect();
    assert_eq!(list.len(), pe.imports.len(), "{ctx}: imported DLLs");
    for (n, d) in list.iter().zip(&pe.imports) {
        assert_eq!(n.val("Name"), d.name.value, "{ctx}: DLL name");
        assert_eq!(
            n.num("ImportLookupTableRVA"),
            u64::from(d.lookup_table.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("ImportAddressTableRVA"),
            u64::from(d.address_table.value),
            "{ctx}"
        );
        let syms: Vec<(String, u64)> = n
            .all("Symbol")
            .map(|s| symbol_and_number(&s.value))
            .collect();
        let ours: Vec<(String, u64)> = d
            .entries
            .iter()
            .map(|e| match (&e.name, e.ordinal) {
                (Some(nm), _) => (
                    nm.value.clone(),
                    e.hint.as_ref().map_or(0, |h| h.value.into()),
                ),
                (None, Some(o)) => (String::new(), o.into()),
                _ => (String::new(), 0),
            })
            .collect();
        assert_eq!(syms, ours, "{ctx}: imports from {}", d.name.value);
    }
    let delay: Vec<&Node> = r.all("DelayImport").collect();
    assert_eq!(
        delay.len(),
        pe.delay_imports.len(),
        "{ctx}: delay-loaded DLLs"
    );
    for (n, d) in delay.iter().zip(&pe.delay_imports) {
        let f = d.delay.as_ref().unwrap();
        assert_eq!(n.val("Name"), d.name.value, "{ctx}");
        assert_eq!(n.num("Attributes"), u64::from(f.attributes.value), "{ctx}");
        assert_eq!(
            n.num("ModuleHandle"),
            u64::from(f.module_handle.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("ImportAddressTable"),
            u64::from(d.address_table.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("ImportNameTable"),
            u64::from(d.lookup_table.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("BoundDelayImportTable"),
            u64::from(f.bound_iat.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("UnloadDelayImportTable"),
            u64::from(f.unload_iat.value),
            "{ctx}"
        );
        let theirs: Vec<(String, u64, u64)> = n
            .all("Import")
            .map(|i| {
                let (nm, h) = symbol_and_number(i.val("Symbol"));
                (nm, h, i.num("Address"))
            })
            .collect();
        let ours: Vec<(String, u64, u64)> = d
            .entries
            .iter()
            .map(|e| {
                (
                    e.name
                        .as_ref()
                        .map_or_else(String::new, |n| n.value.clone()),
                    e.hint
                        .as_ref()
                        .map_or(e.ordinal.map_or(0, u64::from), |h| h.value.into()),
                    e.iat_value.as_ref().map_or(0, |v| v.value),
                )
            })
            .collect();
        assert_eq!(theirs, ours, "{ctx}: delay imports from {}", d.name.value);
    }
}

fn exports(r: &Node, b: &LoadedBinary, ctx: &str) {
    let base = b.pe().unwrap().optional.image_base.value;
    let mut theirs: Vec<(u64, String, String)> = r
        .all("Export")
        .map(|e| {
            let target = match e.get("ForwardedTo") {
                Some(f) => format!("-> {}", f.value),
                None => format!("{:#x}", e.num("RVA")),
            };
            (e.num("Ordinal"), e.val("Name").to_string(), target)
        })
        // Unused address-table slots (RVA 0) are not exports.
        .filter(|(_, n, t)| !(n.is_empty() && t == "0x0"))
        .collect();
    let mut ours: Vec<(u64, String, String)> = b
        .symbols
        .iter()
        .filter(|s| s.table == SymbolTable::Exports)
        .map(|s| {
            let target = match &s.forwarder {
                Some(f) => format!("-> {f}"),
                None => format!("{:#x}", s.va.0 - base),
            };
            (u64::from(s.ordinal.unwrap()), s.name.clone(), target)
        })
        .collect();
    theirs.sort();
    ours.sort();
    same_list(&theirs, &ours, &format!("{ctx}: exports"));
}

fn base_relocs(r: &Node, b: &LoadedBinary, ctx: &str) {
    let theirs: Vec<(String, u64)> = r
        .get("BaseReloc")
        .map(|n| {
            n.all("Entry")
                .map(|e| {
                    // LLVM's names for the ARM MOVW/MOVT pair relocations.
                    let t = match e.val("Type") {
                        "ARM_MOV32(T)" => "THUMB_MOV32",
                        "ARM_MOV32(A)" => "ARM_MOV32",
                        t => t,
                    };
                    (t.to_string(), e.num("Address"))
                })
                .filter(|(t, _)| t != "ABSOLUTE")
                .collect()
        })
        .unwrap_or_default();
    let ours: Vec<(String, u64)> = b
        .relocations
        .iter()
        .filter(|r| r.table == "base relocations")
        .map(|r| {
            let t = r
                .type_name
                .unwrap_or("?")
                .trim_start_matches("IMAGE_REL_BASED_");
            (t.to_string(), r.offset)
        })
        .collect();
    same_list(&theirs, &ours, &format!("{ctx}: base relocations"));
}

fn tls(r: &Node, pe: &PeInfo, ctx: &str) {
    // An empty block means "no TLS directory".
    let Some(n) = r.get("TLSDirectory").filter(|n| !n.children.is_empty()) else {
        assert!(pe.tls.is_none(), "{ctx}: TLS directory");
        return;
    };
    let t = pe.tls.as_ref().expect("TLS directory parsed");
    assert_eq!(
        n.num("StartAddressOfRawData"),
        t.start_address_of_raw_data.value,
        "{ctx}"
    );
    assert_eq!(
        n.num("EndAddressOfRawData"),
        t.end_address_of_raw_data.value,
        "{ctx}"
    );
    assert_eq!(n.num("AddressOfIndex"), t.address_of_index.value, "{ctx}");
    assert_eq!(
        n.num("AddressOfCallBacks"),
        t.address_of_callbacks.value,
        "{ctx}"
    );
    assert_eq!(
        n.num("SizeOfZeroFill"),
        u64::from(t.size_of_zero_fill.value),
        "{ctx}"
    );
    assert_eq!(
        n.num("Characteristics"),
        u64::from(t.characteristics.value),
        "{ctx}"
    );
}

fn guard_list(n: Option<&Node>) -> Vec<u64> {
    n.map(|n| {
        n.children
            .iter()
            .filter_map(|c| num(c.key.split_whitespace().next().unwrap_or("")))
            .collect()
    })
    .unwrap_or_default()
}

fn load_config(r: &Node, pe: &PeInfo, ctx: &str) {
    let Some(n) = r.get("LoadConfig").filter(|n| !n.children.is_empty()) else {
        assert!(pe.load_config.is_none(), "{ctx}: load config");
        return;
    };
    let lc = pe.load_config.as_ref().expect("load config parsed");
    let mut compared = 0;
    for c in &n.children {
        let Some(ours) = lc.get(&c.key) else { continue };
        let Some(theirs) = num(&c.value) else {
            continue;
        };
        assert_eq!(theirs, ours.value, "{ctx}: load config {}", c.key);
        compared += 1;
    }
    assert!(
        compared >= 10,
        "{ctx}: only {compared} load config fields compared"
    );
    let base = pe.optional.image_base.value;
    let va = |v: &[fg_loader::pe::GuardEntry]| -> Vec<u64> {
        v.iter().map(|g| base + u64::from(g.rva)).collect()
    };
    same_list(
        &guard_list(r.get("GuardFidTable")),
        &va(&lc.guard_cf_functions),
        &format!("{ctx}: CFG table"),
    );
    assert_eq!(
        guard_list(r.get("GuardLJmpTable")),
        va(&lc.guard_longjump_targets),
        "{ctx}: longjmp table"
    );
    assert_eq!(
        guard_list(r.get("GuardEHContTable")),
        va(&lc.guard_eh_continuations),
        "{ctx}: EH continuation table"
    );
    let seh: Vec<u64> = lc
        .se_handlers
        .iter()
        .map(|h| base + u64::from(h.value))
        .collect();
    assert_eq!(guard_list(r.get("SEHTable")), seh, "{ctx}: SafeSEH table");
}

fn debug(r: &Node, pe: &PeInfo, ctx: &str) {
    let list: Vec<&Node> = r
        .get("DebugDirectory")
        .map(|d| d.all("DebugEntry").collect())
        .unwrap_or_default();
    assert_eq!(list.len(), pe.debug.len(), "{ctx}: debug entries");
    for (n, d) in list.iter().zip(&pe.debug) {
        assert_eq!(
            n.num("Type"),
            u64::from(d.debug_type.value),
            "{ctx}: debug type"
        );
        assert_eq!(
            n.num("SizeOfData"),
            u64::from(d.size_of_data.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("AddressOfRawData"),
            u64::from(d.address_of_raw_data.value),
            "{ctx}"
        );
        assert_eq!(
            n.num("PointerToRawData"),
            u64::from(d.pointer_to_raw_data.value),
            "{ctx}"
        );
        if let DebugContent::CodeView {
            guid, age, path, ..
        } = &d.content
        {
            let info = n.get("PDBInfo").expect("PDBInfo");
            assert_eq!(info.val("PDBGUID"), guid.value, "{ctx}: PDB GUID");
            assert_eq!(info.num("PDBAge"), u64::from(age.value), "{ctx}: PDB age");
            assert_eq!(info.val("PDBFileName"), path.value, "{ctx}: PDB path");
        }
        if let DebugContent::ExDllCharacteristics(f) = &d.content {
            assert_eq!(
                n.num("ExtendedCharacteristics"),
                u64::from(f.value),
                "{ctx}"
            );
        }
    }
}

fn unwind(u: &Node, pe: &PeInfo, ctx: &str) {
    let Some(list) = u.get("UnwindInformation") else {
        return;
    };
    let base = pe.optional.image_base.value;
    let funcs: Vec<&Node> = list.all("RuntimeFunction").collect();
    match pe.file_header.machine.value {
        fg_loader::pe::consts::IMAGE_FILE_MACHINE_AMD64 => {
            assert_eq!(funcs.len(), pe.exception.len(), "{ctx}: exception entries");
            for (n, f) in funcs.iter().zip(&pe.exception) {
                assert_eq!(
                    n.num("StartAddress"),
                    base + u64::from(f.begin.value),
                    "{ctx}"
                );
                assert_eq!(
                    n.num("EndAddress"),
                    base + u64::from(f.end.unwrap()),
                    "{ctx}"
                );
                assert_eq!(
                    n.num("UnwindInfoAddress"),
                    base + u64::from(f.unwind.value),
                    "{ctx}"
                );
                let (Some(ui), Some(UnwindInfo::X64(x))) = (n.get("UnwindInfo"), &f.info) else {
                    continue;
                };
                assert_eq!(ui.num("Version"), u64::from(x.version), "{ctx}");
                assert_eq!(ui.num("Flags"), u64::from(x.flags.value), "{ctx}");
                assert_eq!(
                    ui.num("PrologSize"),
                    u64::from(x.prolog_size.value),
                    "{ctx}"
                );
                assert_eq!(
                    ui.num("UnwindCodeCount"),
                    u64::from(x.code_count.value),
                    "{ctx}"
                );
                let fr = ui.val("FrameRegister").split(" (").next().unwrap_or("");
                if x.frame_register == 0 {
                    assert_eq!(fr, "-", "{ctx}: frame register");
                } else {
                    assert_eq!(fr, x64_reg(x.frame_register), "{ctx}: frame register");
                }
                let codes: Vec<&Node> = ui
                    .get("UnwindCodes")
                    .map(|c| c.children.iter().collect())
                    .unwrap_or_default();
                assert_eq!(
                    codes.len(),
                    x.codes.len(),
                    "{ctx}: unwind codes at {:#x}",
                    f.begin.value
                );
                for (c, ours) in codes.iter().zip(&x.codes) {
                    assert_eq!(
                        num(&c.key),
                        Some(u64::from(ours.offset)),
                        "{ctx}: code offset"
                    );
                    let mut parts = c.value.split([' ', ',']).filter(|p| !p.is_empty());
                    assert_eq!(
                        parts.next(),
                        Some(ours.op),
                        "{ctx}: code op at {:#x}",
                        f.begin.value
                    );
                    for p in parts {
                        match p.split_once('=') {
                            Some(("reg", r)) if ours.op.starts_with("SAVE_XMM") => {
                                assert_eq!(r, format!("XMM{}", ours.register.unwrap()), "{ctx}")
                            }
                            Some(("reg", r)) => {
                                assert_eq!(r, x64_reg(ours.register.unwrap()), "{ctx}")
                            }
                            Some(("size", s)) => {
                                assert_eq!(num(s), ours.value.map(u64::from), "{ctx}")
                            }
                            Some(("offset", s)) => {
                                assert_eq!(num(s), ours.value.map(u64::from), "{ctx}")
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        fg_loader::pe::consts::IMAGE_FILE_MACHINE_ARM64 => {
            assert_eq!(funcs.len(), pe.exception.len(), "{ctx}: exception entries");
            for (n, f) in funcs.iter().zip(&pe.exception) {
                assert_eq!(n.num("Function"), base + u64::from(f.begin.value), "{ctx}");
                match &f.info {
                    Some(UnwindInfo::Arm64Xdata(x)) => {
                        assert_eq!(
                            n.num("ExceptionRecord"),
                            base + u64::from(f.unwind.value),
                            "{ctx}"
                        );
                        let d = n.get("ExceptionData").expect("ExceptionData");
                        assert_eq!(
                            d.num("FunctionLength"),
                            u64::from(x.function_length),
                            "{ctx}"
                        );
                        assert_eq!(d.num("Version"), u64::from(x.version), "{ctx}");
                        assert_eq!(d.val("ExceptionData") == "Yes", x.exception_data, "{ctx}");
                        assert_eq!(d.val("EpiloguePacked") == "Yes", x.epilogue_packed, "{ctx}");
                        assert_eq!(
                            d.num("ByteCodeLength"),
                            u64::from(x.code_words) * 4,
                            "{ctx}"
                        );
                        if !x.epilogue_packed {
                            assert_eq!(
                                d.num("EpilogueScopes"),
                                u64::from(x.epilogue_count),
                                "{ctx}"
                            );
                        }
                    }
                    Some(UnwindInfo::Arm64Packed(p)) => {
                        assert_eq!(
                            n.num("FunctionLength"),
                            u64::from(p.function_length),
                            "{ctx}: packed length"
                        );
                        assert_eq!(n.num("RegF"), u64::from(p.reg_f), "{ctx}");
                        assert_eq!(n.num("RegI"), u64::from(p.reg_i), "{ctx}");
                        assert_eq!(n.num("CR"), u64::from(p.cr), "{ctx}");
                        assert_eq!(n.num("FrameSize"), u64::from(p.frame_size), "{ctx}");
                    }
                    other => panic!("{ctx}: unexpected ARM64 unwind data {other:?}"),
                }
            }
        }
        _ => {}
    }
}

fn symbols(s: &Node, b: &LoadedBinary, ctx: &str) {
    let theirs: Vec<(String, u64, u64)> = s
        .get("Symbols")
        .map(|l| {
            l.all("Symbol")
                .map(|n| {
                    (
                        n.val("Name").to_string(),
                        n.num("Value"),
                        n.num("StorageClass"),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let pe = b.pe().unwrap();
    let ours: Vec<(String, u64, u64)> = pe
        .coff_symbols
        .iter()
        .map(|c| {
            (
                c.name.clone(),
                u64::from(c.value.value),
                u64::from(c.storage_class.value),
            )
        })
        .collect();
    same_list(&theirs, &ours, &format!("{ctx}: COFF symbols"));
}

fn resource_name(v: &str) -> ResourceName {
    match v.rfind("(ID ") {
        Some(i) => ResourceName::Id(num(v[i + 4..].trim_end_matches(')')).unwrap() as u32),
        None => ResourceName::Name(v.trim().to_string()),
    }
}

fn resources(r: &Node, pe: &PeInfo, ctx: &str) {
    let Some(root) = r.get("Resources") else {
        assert!(pe.resources.is_empty(), "{ctx}: resources");
        return;
    };
    let mut theirs: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for t in root.all("Type") {
        for n in t.all("Name") {
            for l in n.all("Language") {
                let d = l.get("Data").expect("Data");
                let key = format!(
                    "{:?}/{:?}/{:?}",
                    resource_name(&t.value),
                    resource_name(&n.value),
                    resource_name(&l.value)
                );
                theirs.insert(
                    key,
                    (d.num("DataRVA"), d.num("DataSize"), d.num("Codepage")),
                );
            }
        }
    }
    let ours: BTreeMap<String, (u64, u64, u64)> = pe
        .resources
        .iter()
        .map(|res| {
            let key = res
                .path
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join("/");
            (
                key,
                (
                    u64::from(res.data_rva.value),
                    u64::from(res.size.value),
                    u64::from(res.code_page.value),
                ),
            )
        })
        .collect();
    assert_eq!(theirs, ours, "{ctx}: resources");
}

// ---------------------------------------------------------------- objdump

#[test]
fn matches_objdump() {
    if !run_ok(Command::new("objdump").arg("--version")) {
        eprintln!("note: objdump not found, oracle skipped");
        return;
    }
    let mut checked = 0;
    for path in inputs() {
        let Some(b) = load_file(path) else { continue };
        let pe = b.pe().unwrap();
        let ctx = path.display().to_string();
        let out = Command::new("objdump")
            .arg("-p")
            .arg(path)
            .output()
            .unwrap();
        if !out.status.success() {
            continue; // e.g. ARM64 images without an aarch64 BFD target
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |k: &str| -> Option<u64> {
            text.lines().find_map(|l| {
                let mut it = l.split_whitespace();
                (it.next() == Some(k))
                    .then(|| it.next().and_then(|v| u64::from_str_radix(v, 16).ok()))
                    .flatten()
            })
        };
        let o = &pe.optional;
        for (k, ours) in [
            ("ImageBase", o.image_base.value),
            ("SectionAlignment", o.section_alignment.value.into()),
            ("FileAlignment", o.file_alignment.value.into()),
            ("SizeOfImage", o.size_of_image.value.into()),
            ("SizeOfHeaders", o.size_of_headers.value.into()),
            ("CheckSum", o.checksum.value.into()),
            ("DllCharacteristics", o.dll_characteristics.value.into()),
            ("AddressOfEntryPoint", o.address_of_entry_point.value.into()),
        ] {
            if let Some(v) = field(k) {
                assert_eq!(v, ours, "{ctx}: objdump {k}");
            }
        }
        // "DLL Name: KERNEL32.dll", in table order (objdump does not list delay imports).
        let dlls: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("DLL Name: "))
            .collect();
        let ours: Vec<&str> = pe.imports.iter().map(|d| d.name.value.as_str()).collect();
        if !dlls.is_empty() || ours.is_empty() {
            assert_eq!(dlls, ours, "{ctx}: objdump DLL names");
        }
        checked += 1;
        eprintln!("ok  objdump  {ctx}");
    }
    eprintln!("objdump oracle: {checked} files compared");
}

// ---------------------------------------------------------------- whole-file facts

/// The checksum algorithm matches what linkers and signing tools store.
#[test]
fn checksums_match_stored_values() {
    let mut checked = 0;
    for path in inputs() {
        let Some(b) = load_file(path) else { continue };
        let pe = b.pe().unwrap();
        let stored = pe.optional.checksum.value;
        let truncated = b
            .anomalies
            .iter()
            .any(|a| a.code == "pe.section.raw_outside");
        if stored == 0 || truncated {
            continue;
        }
        assert_eq!(pe.computed_checksum, stored, "{}: checksum", path.display());
        checked += 1;
    }
    eprintln!("checksum oracle: {checked} files with a stored checksum");
}

/// Real toolchain output never trips structural anomalies.
#[test]
fn real_files_have_no_structural_anomalies() {
    const EXPECTED: &[&str] = &[
        "pe.tls.callbacks",
        "pe.clr",
        "pe.chpe",
        "pe.overlay",
        "pe.optional.rva_count",
        "pe.machine.unknown",
    ];
    for path in inputs() {
        let Some(b) = load_file(path) else { continue };
        if b.anomalies
            .iter()
            .any(|a| a.code == "pe.section.raw_outside")
        {
            continue; // deliberately truncated test data
        }
        let odd: Vec<String> = b
            .anomalies
            .iter()
            .filter(|a| !EXPECTED.contains(&a.code))
            .map(|a| format!("{} {}", a.code, a.message))
            .collect();
        assert!(odd.is_empty(), "{}: {odd:#?}", path.display());
    }
}

/// Every code seed lands inside an executable section, and named seeds agree with symbols.
#[test]
fn seeds_point_at_code() {
    for path in inputs() {
        let Some(b) = load_file(path) else { continue };
        if b.anomalies
            .iter()
            .any(|a| a.code == "pe.section.raw_outside")
        {
            continue;
        }
        for s in &b.seeds {
            let seg = b.segments.iter().skip(1).find(|g| g.contains(s.va));
            assert!(
                seg.is_some_and(|g| g.perms.execute),
                "{}: {:?} seed {} is not in an executable section",
                path.display(),
                s.kind,
                s.va
            );
        }
    }
}
