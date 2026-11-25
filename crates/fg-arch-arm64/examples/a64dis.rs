// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Development aid: reads 32-bit words (hex, one per line) and prints
//! `word<TAB>encoding<TAB>text` for each (`<invalid>` for words that do not
//! decode). Instructions are placed at address 0, so targets read as offsets.

use fg_core::Va;
use fg_ir::{Arch, Mode, Syntax, tokens_text};
use std::io::{BufRead, BufWriter, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("read");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let w = u32::from_str_radix(line.trim_start_matches("0x"), 16).expect("hex word");
        let bytes = w.to_le_bytes();
        let text = match fg_arch_arm64::ARM64.decode(&bytes, Va(0), Mode::Native) {
            Ok(insn) => tokens_text(&fg_arch_arm64::ARM64.format(&insn, Syntax::Intel)),
            Err(_) => "<invalid>".into(),
        };
        let mut name = fg_arch_arm64::encoding_name(w).unwrap_or("-").to_string();
        if fg_arch_arm64::is_unpredictable(w) {
            name.push('!');
        }
        writeln!(out, "{w:08x}\t{name}\t{text}").expect("write");
    }
}
