// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Text rendering of disassembly listings.

use fg_service::disasm::{InsnLine, Line};
use fg_service::ir::{DecodeError, Token, TokenKind};
use fg_service::loader::{LoadedBinary, SeedKind};
use std::fmt::Write;

/// Bytes shown per line before the text column (longer instructions push it right).
const BYTES_COLUMN: usize = 7 * 3;
/// Width the mnemonic (with any prefixes) is padded to, as `objdump` does.
const MNEMONIC_COLUMN: usize = 7;

/// Hex digits needed for the highest address in the binary, so the address
/// column lines up without seeing the whole listing first.
pub fn address_width(b: &LoadedBinary) -> usize {
    let top = b
        .segments
        .iter()
        .map(|s| s.va.0.saturating_add(s.mem_size))
        .chain(
            b.sections
                .iter()
                .filter_map(|s| s.va.map(|v| v.0.saturating_add(s.size))),
        )
        .max()
        .unwrap_or(0);
    format!("{top:x}").len()
}

/// Renders one listing line (with its trailing newline).
pub fn line(o: &mut String, line: &Line, width: usize) {
    match line {
        Line::Region { name, start, end } => {
            let _ = writeln!(o, "\nsection {name}  {start}..{end}");
        }
        Line::Label { va, names, seeds } => {
            let _ = write!(o, "\n{:0width$x}", va.0);
            for n in names {
                let _ = write!(o, " <{n}>");
            }
            o.push(':');
            if !seeds.is_empty() {
                let kinds: Vec<&str> = seeds.iter().map(|k| seed_name(*k)).collect();
                let _ = write!(o, "    ; {}", kinds.join(", "));
            }
            o.push('\n');
        }
        Line::Insn(i) => insn_line(o, i, width),
        Line::Bad { va, bytes, error } => {
            let hex = hex_bytes(bytes);
            let why = match error {
                DecodeError::Truncated => "instruction runs past the end of the code",
                _ => "invalid instruction",
            };
            let _ = writeln!(
                o,
                "  {:>width$x}:  {hex:<BYTES_COLUMN$}  {:<MNEMONIC_COLUMN$}; {why}",
                va.0, "(bad)"
            );
        }
        _ => {}
    }
}

fn seed_name(k: SeedKind) -> &'static str {
    match k {
        SeedKind::Entry => "entry point",
        SeedKind::Init => "DT_INIT",
        SeedKind::Fini => "DT_FINI",
        SeedKind::PreinitArray => "preinit_array",
        SeedKind::InitArray => "init_array (constructor)",
        SeedKind::FiniArray => "fini_array (destructor)",
        SeedKind::TlsCallback => "TLS callback",
        SeedKind::ExceptionTable => "exception table",
        SeedKind::ExceptionFragment => "exception table (fragment)",
        SeedKind::CfgTarget => "CFG target",
        SeedKind::SehHandler => "SafeSEH handler",
        SeedKind::UnwindTable => ".eh_frame",
        SeedKind::UnwindFragment => ".eh_frame (fragment)",
        SeedKind::UnwindSignal => ".eh_frame (signal trampoline)",
        _ => "seed",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The instruction text with the mnemonic padded to a column.
pub fn insn_text(tokens: &[Token]) -> String {
    let mut s = String::new();
    let mut iter = tokens.iter().peekable();
    let mut padded = false;
    while let Some(t) = iter.next() {
        s.push_str(&t.text);
        if !padded && t.kind == TokenKind::Mnemonic {
            padded = true;
            if iter.peek().is_some_and(|n| n.kind == TokenKind::Space) {
                iter.next();
                while s.len() < MNEMONIC_COLUMN - 1 {
                    s.push(' ');
                }
                s.push(' ');
            }
        }
    }
    s
}

fn insn_line(o: &mut String, i: &InsnLine, width: usize) {
    let hex = hex_bytes(i.insn.bytes.as_slice());
    let _ = write!(
        o,
        "  {:>width$x}:  {hex:<BYTES_COLUMN$}  {}",
        i.insn.va.0,
        insn_text(&i.tokens)
    );
    if i.overlaps_label {
        o.push_str("  ; overlaps the next label, which is decoded separately");
    }
    o.push('\n');
}
