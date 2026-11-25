// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Repository maintenance tasks.
//!
//! `cargo xtask layers` enforces the architecture rule from the design document
//! (section 22.8): a crate may only depend on crates in a strictly lower layer.
//! The table below is the single source of truth for crate layering; adding a
//! crate to the workspace without adding it here fails the check.
//!
//! `cargo xtask measure CORPUS` scores function recovery against a corpus's
//! true function lists (see `measure.rs`).

mod measure;

use std::collections::BTreeMap;
use std::process::{Command, ExitCode};

/// Layer of every Fulgurite crate, lowest first (design document section 22.8).
const LAYERS: &[(&str, u32)] = &[
    ("fg-core", 0),
    ("fg-loader", 1),
    ("fg-ir", 1),
    ("fg-facts", 1),
    ("fg-arch-x86", 2),
    ("fg-arch-arm64", 2),
    ("fg-store", 2),
    ("fg-analysis", 3),
    ("fg-decomp", 4),
    ("fg-dynamic", 4),
    ("fg-solve", 4),
    ("fg-learn", 5),
    ("fg-service", 6),
    ("fulgurited", 7),
    ("fg-cli", 7),
    ("fg-py", 7),
];

/// Workspace members that are tooling, not part of the product.
const TOOLING: &[&str] = &["xtask"];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("layers") => layers(),
        Some("measure") => measure::measure(&args[1..]),
        _ => {
            eprintln!("usage: cargo xtask layers | cargo xtask measure CORPUS");
            ExitCode::from(2)
        }
    }
}

fn layers() -> ExitCode {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = match Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("could not run cargo metadata: {e}");
            return ExitCode::FAILURE;
        }
    };
    let meta: serde_json::Value = match serde_json::from_slice(&out) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bad cargo metadata output: {e}");
            return ExitCode::FAILURE;
        }
    };
    let layer: BTreeMap<&str, u32> = LAYERS.iter().copied().collect();
    let mut problems = Vec::new();
    let mut checked = 0;

    for pkg in meta["packages"].as_array().into_iter().flatten() {
        let name = pkg["name"].as_str().unwrap_or("?");
        if TOOLING.contains(&name) {
            continue;
        }
        let Some(&own) = layer.get(name) else {
            problems.push(format!(
                "{name}: not in the layer table in xtask/src/main.rs"
            ));
            continue;
        };
        checked += 1;
        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            let dep_name = dep["name"].as_str().unwrap_or("?");
            if dep["path"].is_null() {
                continue; // external crate
            }
            let kind = dep["kind"].as_str().unwrap_or("normal");
            match layer.get(dep_name) {
                Some(&d) if d < own => {}
                Some(&d) if kind == "dev" && d <= own => {} // tests may use same-layer helpers
                Some(&d) => problems.push(format!(
                    "{name} (layer {own}) depends on {dep_name} (layer {d}); dependencies must point to a lower layer"
                )),
                None => problems.push(format!("{name} depends on {dep_name}, which is not in the layer table")),
            }
        }
    }

    if problems.is_empty() {
        println!("layers ok: {checked} crates, every internal dependency points downward");
        ExitCode::SUCCESS
    } else {
        for p in &problems {
            eprintln!("layering violation: {p}");
        }
        ExitCode::FAILURE
    }
}
