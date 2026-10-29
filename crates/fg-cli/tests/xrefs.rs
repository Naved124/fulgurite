//! `fulg xrefs` on the `fulg` executable itself.

use std::process::Command;

#[test]
fn lists_references_by_name_and_address() {
    let fulg = env!("CARGO_BIN_EXE_fulg");
    if fg_service::loader::detect(&std::fs::read(fulg).unwrap())
        != Some(fg_service::loader::Format::Elf)
    {
        eprintln!("note: not an ELF build; skipped");
        return;
    }
    let json = |args: &[&str]| -> serde_json::Value {
        let out = Command::new(fulg).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    // `_start` hands `main` to the C library: it takes its address.
    let v = json(&["xrefs", "--json", fulg, "main"]);
    assert_eq!(v["schema"], "fulgurite.xrefs.v1");
    let main = v["target"].as_u64().unwrap();
    let refs = v["xrefs"].as_array().unwrap();
    assert!(!refs.is_empty());
    assert!(refs.iter().all(|r| r["to"].as_u64() >= Some(main)));
    assert!(
        refs.iter().any(|r| r["kind"] == "Address"
            && r["from_name"]
                .as_str()
                .is_some_and(|n| n.starts_with("_start"))),
        "{refs:?}"
    );
    // The same references as text, the target given as an address.
    let text = Command::new(fulg)
        .args(["xrefs", fulg, &format!("{main:#x}")])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.starts_with(&format!("{} reference", refs.len())),
        "{text}"
    );
    assert!(text.contains(" main"), "{text}");
    assert!(text.contains("address"), "{text}");

    // A name nothing has fails before any analysis.
    let none = Command::new(fulg)
        .args(["xrefs", fulg, "no_such_symbol_anywhere"])
        .output()
        .unwrap();
    assert!(!none.status.success());
    assert!(String::from_utf8_lossy(&none.stderr).contains("no label or symbol is named"));
}
