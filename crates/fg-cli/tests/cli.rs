//! End-to-end tests of the `fulg` binary.

use std::process::Command;

fn fulg() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fulg"))
}

fn real_binary() -> Option<&'static str> {
    ["/bin/cat", "/bin/ls", "/bin/sh"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
}

#[test]
fn info_text_has_every_section() {
    let Some(file) = real_binary() else { return };
    let out = fulg().args(["info", file]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for needle in [
        "File",
        "Format",
        "Type",
        "Machine",
        "Entry",
        "Program headers",
        "Mitigations",
        "PIE",
        "NX",
        "RELRO",
        "Canary",
        "Anomalies",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
    assert!(
        text.contains("@0x18..0x1f") || text.contains("@0x18..0x1b"),
        "entry provenance shown"
    );
}

#[test]
fn info_json_is_valid_and_versioned() {
    let Some(file) = real_binary() else { return };
    let out = fulg().args(["info", "--json", file]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "fulgurite.info.v1");
    assert_eq!(v["binary"]["format"], "Elf");
    assert!(v["binary"]["entry"]["span"]["offset"].is_u64());
    assert!(v["binary"]["mitigations"]["nx"]["evidence"].is_array());
}

#[test]
fn not_an_elf_exits_2() {
    let out = fulg()
        .args(["info", env!("CARGO_MANIFEST_DIR")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "a directory is an I/O error");
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = fulg().args(["info", manifest]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognised file format"));
}

#[test]
fn missing_file_exits_1() {
    let out = fulg()
        .args(["info", "/definitely/not/here"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn malformed_elf_lists_anomalies() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = format!("{dir}/bad_class.elf");
    let mut bytes = b"\x7fELF\x07\x01\x01".to_vec();
    bytes.resize(64, 0);
    std::fs::write(&path, bytes).unwrap();
    let out = fulg().args(["info", &path]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("elf.ident.class"), "{err}");
}

#[test]
fn sections_command() {
    let Some(file) = real_binary() else { return };
    let out = fulg().args(["sections", file]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(".text") && text.contains(".dynsym"), "{text}");
    let json = fulg().args(["sections", "--json", file]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["schema"], "fulgurite.sections.v1");
    assert!(
        v["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == ".text")
    );
}

#[test]
fn symbols_command_filters() {
    let Some(file) = real_binary() else { return };
    let json = |args: &[&str]| -> serde_json::Value {
        let out = fulg()
            .args(["symbols", "--json"])
            .args(args)
            .arg(file)
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let all = json(&[]);
    assert_eq!(all["schema"], "fulgurite.symbols.v1");
    let imports = json(&["--imports"]);
    let list = imports["symbols"].as_array().unwrap();
    assert!(!list.is_empty());
    assert!(
        list.iter()
            .all(|s| s["defined"] == false && s["table"] == "Dynamic")
    );
    assert!(list.len() < all["symbols"].as_array().unwrap().len());
    let text = String::from_utf8(
        fulg()
            .args(["symbols", "--imports", file])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(text.contains("@GLIBC_"), "imports carry versions:\n{text}");
    let conflict = fulg()
        .args(["symbols", "--imports", "--exports", file])
        .output()
        .unwrap();
    assert!(
        !conflict.status.success(),
        "--imports and --exports are exclusive"
    );
}

#[test]
fn relocs_command() {
    let Some(file) = real_binary() else { return };
    let out = fulg().args(["relocs", file]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("R_X86_64_") || text.contains("R_AARCH64_"),
        "{text}"
    );
    let json = |args: &[&str]| -> serde_json::Value {
        let out = fulg()
            .args(["relocs", "--json"])
            .args(args)
            .arg(file)
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let all = json(&[]);
    assert_eq!(all["schema"], "fulgurite.relocs.v1");
    let slots = json(&["--slots"]);
    let list = slots["relocations"].as_array().unwrap();
    assert!(!list.is_empty());
    assert!(
        list.iter()
            .all(|r| r["kind"] == "GotEntry" || r["kind"] == "PltSlot")
    );
    assert!(list.len() < all["relocations"].as_array().unwrap().len());
    assert!(list.iter().any(|r| r["symbol_name"].is_string()));
}

#[test]
fn notes_command() {
    let Some(file) = real_binary() else { return };
    let out = fulg().args(["notes", "--json", file]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "fulgurite.notes.v1");
    assert!(v["notes"].is_array());
    let text = String::from_utf8(fulg().args(["notes", file]).output().unwrap().stdout).unwrap();
    assert!(!text.is_empty());
}

#[test]
fn info_shows_libraries_and_new_checks() {
    let Some(file) = real_binary() else { return };
    let text = String::from_utf8(fulg().args(["info", file]).output().unwrap().stdout).unwrap();
    for needle in [
        "Libraries",
        "Relocations",
        "Notes",
        "CFI",
        "SepCode",
        "LibPath",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
}

#[path = "../../fg-loader/tests/common/pe.rs"]
mod pe_builder;

/// Writes the synthetic PE with every directory populated and returns its path.
/// The synthetic PE, written once: tests run in parallel, and rewriting the
/// file while another test reads it would hand that test a partial file.
fn sink_pe() -> String {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let path = format!("{}/sink.exe", env!("CARGO_TARGET_TMPDIR"));
        std::fs::write(&path, pe_builder::kitchen_sink()).unwrap();
        path
    })
    .clone()
}

fn text_of(args: &[&str]) -> String {
    let out = fulg().args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn pe_info_text_and_json() {
    let f = sink_pe();
    let text = text_of(&["info", &f]);
    for needle in [
        "PE32+ (64-bit)",
        "Machine      x86-64",
        "Image base   0x140000000",
        "KERNEL32.dll",
        "Delay-loaded USER32.dll",
        "Memory map",
        "Data directories",
        "Exception table  1 functions with unwind data, 1 fragments",
        "Load config",
        "Code seeds",
        "SafeSEH",
        "Signature",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
    let out = fulg().args(["info", "--json", &f]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "fulgurite.info.v1");
    assert_eq!(v["binary"]["format"], "Pe");
    assert!(v["binary"]["metadata"]["Pe"]["load_config"]["fields"].is_array());
    assert_eq!(
        v["binary"]["mitigations"]["seh"]["verdict"],
        "NotApplicable"
    );
}

#[test]
fn pe_listing_commands() {
    let f = sink_pe();
    let imports = text_of(&["imports", &f]);
    assert!(
        imports.contains("ExitProcess") && imports.contains("#5 (by ordinal)"),
        "{imports}"
    );
    assert!(imports.contains("delay-loaded"), "{imports}");
    let exports = text_of(&["exports", &f]);
    assert!(
        exports.contains("go") && exports.contains("-> K.Sleep"),
        "{exports}"
    );
    let seeds = text_of(&["seeds", &f]);
    for k in [
        "Entry",
        "TlsCallback",
        "ExceptionTable",
        "ExceptionFragment",
        "CfgTarget",
    ] {
        assert!(seeds.contains(k), "missing {k} in:\n{seeds}");
    }
    let relocs = text_of(&["relocs", &f]);
    for t in ["IAT ", "delay IAT ", "base relocations "] {
        assert!(relocs.contains(t), "missing {t:?} in:\n{relocs}");
    }
    assert!(relocs.contains("KERNEL32.dll!ExitProcess"));
    assert!(text_of(&["resources", &f]).contains("RCDATA"));
    assert!(text_of(&["notes", &f]).contains("PDB GUID"));
    assert!(text_of(&["sections", &f]).contains(".pdata"));
    let syms = text_of(&["symbols", "--imports", &f]);
    assert!(
        syms.contains("KERNEL32.dll!#5") && !syms.contains("export"),
        "{syms}"
    );
    for (cmd, schema, key) in [
        ("imports", "fulgurite.imports.v1", "imports"),
        ("exports", "fulgurite.exports.v1", "exports"),
        ("seeds", "fulgurite.seeds.v1", "seeds"),
        ("resources", "fulgurite.resources.v1", "resources"),
    ] {
        let out = fulg().args([cmd, "--json", &f]).output().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["schema"], schema);
        assert!(!v[key].as_array().unwrap().is_empty(), "{cmd}");
    }
    let out = fulg().args(["notes", "--json", &f]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["debug_directory"].is_array());
}

#[test]
fn neutral_commands_on_elf() {
    let Some(file) = real_binary() else { return };
    assert!(text_of(&["seeds", file]).contains("Entry"));
    assert!(text_of(&["imports", file]).contains("libc.so.6"));
    assert!(text_of(&["exports", file]).contains("export"));
    assert!(text_of(&["resources", file]).contains("Only PE files"));
    let out = fulg().args(["notes", "--json", file]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.get("debug_directory").is_none(),
        "PE-only keys are omitted for ELF"
    );
}

#[test]
fn not_a_pe_dos_program_exits_2() {
    let path = format!("{}/dos.exe", env!("CARGO_TARGET_TMPDIR"));
    let mut b = vec![0u8; 0x80];
    b[0] = b'M';
    b[1] = b'Z';
    std::fs::write(&path, &b).unwrap();
    let out = fulg().args(["info", &path]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pe.nt.signature"));
}

#[test]
fn disasm_text_json_and_targets() {
    let Some(bin) = real_binary() else {
        eprintln!("note: no system binary; skipped");
        return;
    };
    let text = text_of(&["disasm", bin]);
    assert!(
        text.contains("\nsection .text  0x"),
        "{}",
        &text[..text.len().min(400)]
    );
    assert!(text.contains("; entry point"));
    // A count from the entry point: the label, then exactly three instructions.
    let three = text_of(&["disasm", bin, "entry", "-n", "3"]);
    let insn_lines = three.lines().filter(|l| l.starts_with("  ")).count();
    assert_eq!(insn_lines, 3, "{three}");
    // AT&T syntax.
    assert!(text_of(&["disasm", bin, "entry", "-n", "4", "--att"]).contains('%'));
    // JSON: versioned, one object per line, each instruction with its text.
    let json: serde_json::Value =
        serde_json::from_str(&text_of(&["disasm", bin, "entry", "-n", "5", "--json"])).unwrap();
    assert_eq!(json["schema"], "fulgurite.disasm.v1");
    assert_eq!(json["syntax"], "intel");
    let insns: Vec<&serde_json::Value> = json["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["line"] == "insn")
        .collect();
    assert_eq!(insns.len(), 5);
    assert!(insns[0]["text"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(insns[0]["insn"]["bytes"].as_str().is_some());
}

#[test]
fn disasm_errors_and_closed_pipes() {
    let Some(bin) = real_binary() else {
        return;
    };
    for (args, needle) in [
        (
            vec!["disasm", bin, "no_such_function_xyz"],
            "no defined symbol",
        ),
        (
            vec!["disasm", bin, "0x7fffffff0000"],
            "not backed by file bytes",
        ),
        (
            vec!["disasm", bin, "entry", "--end", "zz"],
            "not a hexadecimal address",
        ),
        (vec!["disasm", bin, "-s", ".nope"], "no section named"),
    ] {
        let out = fulg().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(needle),
            "{args:?}"
        );
    }
    // Reading only the first line must not make fulg panic.
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "'{}' disasm {bin} | head -n 1",
            env!("CARGO_BIN_EXE_fulg")
        ))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn disasm_pe() {
    let path = sink_pe();
    let text = text_of(&["disasm", &path]);
    assert!(text.contains("section .text"), "{text}");
    assert!(text.contains("; entry point"));
}
