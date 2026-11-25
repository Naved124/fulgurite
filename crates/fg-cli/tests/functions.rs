// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! `fulg functions` on the `fulg` executable itself.

use std::process::Command;

#[test]
fn lists_functions_with_evidence() {
    let fulg = env!("CARGO_BIN_EXE_fulg");
    if fg_service::loader::detect(&std::fs::read(fulg).unwrap())
        != Some(fg_service::loader::Format::Elf)
    {
        eprintln!("note: not an ELF build; skipped");
        return;
    }
    let out = Command::new(fulg)
        .args(["functions", "--json", fulg])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], "fulgurite.functions.v1");
    let funcs = v["functions"].as_array().unwrap();
    assert!(funcs.len() > 1000);
    for f in funcs {
        assert!(!f["evidence"].as_array().unwrap().is_empty(), "{f}");
        let c = f["confidence"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&c));
    }
    assert!(
        funcs
            .iter()
            .any(|f| f["name"] == "main" && f["found_by"] == "seeds")
    );
    // Rust's panic machinery never returns; `main` does.
    let never = |f: &serde_json::Value| !f["no_return"].as_array().unwrap().is_empty();
    assert!(funcs.iter().any(never));
    assert!(!funcs.iter().any(|f| f["name"] == "main" && never(f)));

    let text = Command::new(fulg)
        .args(["functions", fulg])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains(" main\n") || text.contains(" main ["));
    assert!(text.contains(&format!("{} functions, ", funcs.len())));
}
