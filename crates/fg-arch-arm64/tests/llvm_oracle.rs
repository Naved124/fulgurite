// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Cross-checks the decoder against LLVM's disassembler (`llvm-mc`).
//!
//! Words: pseudo-random 32-bit values (a uniform sample of the encoding space)
//! plus a few words from inside every encoding. For each, llvm-mc and
//! Fulgurite must agree on whether it is an instruction and, if so, on the
//! text after normalisation. Differences are accepted only in the documented
//! categories below, each counted; anything else fails the test.
//!
//! Environment: `FULG_LLVM_MC` (llvm-mc to run), `FULG_A64_ORACLE_WORDS`
//! (random words, default 60000), `FULG_A64_ORACLE_PER_ENCODING` (words per
//! encoding, default 3), `FULG_A64_ORACLE_SEED`. The test needs LLVM 23 or
//! newer (older releases lack instructions the 2026 specification has) and
//! skips with a note otherwise. The exhaustive run over all 2^32 words uses
//! the same comparison (see docs/progress/m0-step6.md).
#![allow(missing_docs)]

use fg_arch_arm64::{
    ARM64, encoding_name, encodings, encodings_not_decoded, is_unpredictable, system_register,
    system_register_names,
};
use fg_core::Va;
use fg_ir::{Arch, Mode, Syntax, tokens_text};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn llvm_mc() -> String {
    std::env::var("FULG_LLVM_MC").unwrap_or_else(|_| "llvm-mc".into())
}

/// LLVM's major version, if llvm-mc runs and knows AArch64.
fn llvm_version() -> Option<u32> {
    let out = Command::new(llvm_mc()).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("aarch64") {
        return None;
    }
    let v = text.split("LLVM version ").nth(1)?;
    v.split('.').next()?.trim().parse().ok()
}

/// llvm-mc's view of a set of words.
#[derive(Default)]
struct Llvm {
    /// Text of every word it decodes; words it rejects are absent.
    text: HashMap<u32, String>,
    /// Words it decodes with "potentially undefined instruction encoding"
    /// (LLVM's SoftFail: bits it expects to have a value do not).
    soft: HashSet<u32>,
}

/// Disassembles `words` with llvm-mc, one word per input line. Output is
/// matched to input by position: llvm-mc reports each word it rejects on
/// stderr with its line number and prints every other word in order. (The
/// re-encoded bytes it prints cannot be used as the key: a word LLVM decodes
/// but encodes differently would look rejected.)
fn llvm(words: &[u32]) -> Llvm {
    let mut input = String::with_capacity(words.len() * 20);
    for w in words {
        let b = w.to_le_bytes();
        input.push_str(&format!(
            "{:#04x} {:#04x} {:#04x} {:#04x}\n",
            b[0], b[1], b[2], b[3]
        ));
    }
    let (out, err) = run_llvm(&["--disassemble", "-show-encoding"], &input);
    let line_of = |diag: &str| -> Option<usize> {
        diag.strip_prefix("<stdin>:")?
            .split(':')
            .next()?
            .parse::<usize>()
            .ok()
            .map(|n| n - 1)
    };
    let mut invalid = HashSet::new();
    let mut soft = HashSet::new();
    for diag in err.lines() {
        if diag.ends_with("warning: invalid instruction encoding") {
            invalid.extend(line_of(diag));
        } else if diag.ends_with("warning: potentially undefined instruction encoding") {
            soft.extend(line_of(diag));
        }
    }
    // Instruction lines carry the encoding; printer comments get lines of their own.
    let mut texts = out
        .lines()
        .filter_map(|l| Some(l.split_once("// encoding: [")?.0.trim().to_string()));
    let mut res = Llvm::default();
    for (i, &w) in words.iter().enumerate() {
        if invalid.contains(&i) {
            continue;
        }
        let text = texts
            .next()
            .expect("llvm-mc printed fewer instructions than words");
        if soft.contains(&i) {
            res.soft.insert(w);
        }
        res.text.insert(w, text);
    }
    assert!(
        texts.next().is_none(),
        "llvm-mc printed more instructions than words"
    );
    res
}

/// Mnemonics llvm-mc does not know at all (newer architecture extensions):
/// assembling one line reports "unrecognized instruction mnemonic".
fn unknown_to_llvm(texts: &[String]) -> HashSet<usize> {
    let input: String = texts.iter().map(|t| format!("{t}\n")).collect();
    let mut child = Command::new(llvm_mc())
        .args(["-triple=aarch64", "-mattr=+all", "-o", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("llvm-mc");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.contains("unrecognized instruction mnemonic"))
        .filter_map(|l| l.split(':').nth(1)?.parse::<usize>().ok())
        .map(|line| line - 1)
        .collect()
}

/// Runs llvm-mc on `input`; returns stdout and stderr.
fn run_llvm(args: &[&str], input: &str) -> (String, String) {
    let mut child = Command::new(llvm_mc())
        .args(["-triple=aarch64", "-mattr=+all"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("llvm-mc");
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_string();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Our text at address 0, so branch targets read as offsets like llvm-mc's.
fn ours(w: u32) -> Option<String> {
    let insn = ARM64.decode(&w.to_le_bytes(), Va(0), Mode::Native).ok()?;
    Some(tokens_text(&ARM64.format(&insn, Syntax::Intel)))
}

// ---------------------------------------------------------------------------
// Normalisation

fn squash(t: &str) -> String {
    let t = t.replace('\t', " ").to_lowercase();
    let mut out = String::new();
    for word in t.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    // "{ z0.b }" and "{z0.b}"
    out.replace("{ ", "{").replace(" }", "}")
}

/// `{z1.d - z3.d}` / `{z1.d-z3.d}` to `{z1.d, z2.d, z3.d}` (wrapping at 32).
fn expand_ranges(t: &str) -> String {
    let mut out = String::new();
    let mut rest = t;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        let inner = &rest[open + 1..open + close];
        let parts: Vec<&str> = inner.split('-').map(str::trim).collect();
        let reg = |s: &str| -> Option<(String, u32, String)> {
            let letters: String = s.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            let rest = &s[letters.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let n = digits.parse().ok()?;
            Some((letters, n, rest[digits.len()..].to_string()))
        };
        match (
            parts.len(),
            parts.first().and_then(|a| reg(a)),
            parts.get(1).and_then(|b| reg(b)),
        ) {
            (2, Some((pa, a, sa)), Some((pb, b, _))) if pa == pb && !inner.contains(',') => {
                let n = (b + 32 - a) % 32 + 1;
                let list: Vec<String> = (0..n)
                    .map(|k| format!("{pa}{}{sa}", (a + k) % 32))
                    .collect();
                out.push('{');
                out.push_str(&list.join(", "));
                out.push('}');
            }
            _ => out.push_str(&rest[open..=open + close]),
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

fn norm_llvm(t: &str) -> String {
    expand_ranges(&squash(t))
}

/// Our absolute addresses (`0x...` not after `#`) as llvm-mc's signed offsets.
fn norm_ours(t: &str) -> String {
    let t = squash(t);
    let mut out = String::new();
    let mut words = t.split(' ').peekable();
    while let Some(w) = words.next() {
        let (core, tail) = match w.strip_suffix(',') {
            Some(c) => (c, ","),
            None => (w, ""),
        };
        if let Some(hex) = core.strip_prefix("0x")
            && let Ok(v) = u64::from_str_radix(hex, 16)
        {
            out.push_str(&format!("#{}{tail}", v as i64));
        } else {
            out.push_str(w);
        }
        if words.peek().is_some() {
            out.push(' ');
        }
    }
    expand_ranges(&out)
}

/// Splits into words and numbers so numbers can be compared by value.
fn lex(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in t.chars() {
        if c == ' ' || c == ',' || c == '[' || c == ']' || c == '{' || c == '}' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            if c != ' ' {
                out.push(c.to_string());
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn number(tok: &str) -> Option<i128> {
    let t = tok.strip_prefix('#').unwrap_or(tok);
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let v = match t.strip_prefix("0x") {
        Some(h) => i128::from_str_radix(h, 16).ok()?,
        None if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) => t.parse().ok()?,
        None => return None,
    };
    Some(if neg { -v } else { v })
}

/// SVE `#a, lsl #8` written by llvm-mc as one value.
fn merge_lsl8(tokens: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if i + 3 < tokens.len()
            && tokens[i + 1] == ","
            && tokens[i + 2] == "lsl"
            && tokens[i + 3] == "#8"
            && let Some(v) = number(&tokens[i])
            && tokens[i].starts_with('#')
        {
            out.push(format!("#{}", v * 256));
            i += 4;
            continue;
        }
        out.push(tokens[i].clone());
        i += 1;
    }
    out
}

/// Same text except the spelling of numbers: decimal and hexadecimal of one
/// value, or the signed and unsigned spellings of the same bits at the operand
/// width (one of them negative). Two different non-negative values never
/// match, so a wrong immediate is not hidden by the width.
fn same_modulo_numbers(o: &str, l: &str) -> bool {
    let to = merge_lsl8(lex(o));
    let tl = merge_lsl8(lex(l));
    if to.len() != tl.len() {
        return false;
    }
    let width = if let Some(p) = o.find('.') {
        match o[p + 1..].chars().next() {
            Some('b') => 8,
            Some('h') => 16,
            Some('s') => 32,
            _ => 64,
        }
    } else if o.split(' ').nth(1).is_some_and(|r| r.starts_with('w')) {
        32
    } else {
        64
    };
    let mask: i128 = (1i128 << width) - 1;
    to.iter().zip(&tl).all(|(a, b)| {
        a == b
            || matches!((number(a), number(b)),
                (Some(x), Some(y)) if x == y || ((x < 0) != (y < 0) && x & mask == y & mask))
    })
}

/// Alias choices where llvm-mc departs from Arm's preferred disassembly, and
/// spellings llvm-mc adds: (ours, llvm) pairs after normalisation.
fn alias_choice(o: &str, l: &str) -> bool {
    // Arm prefers BFC; llvm-mc writes BFI with the zero register.
    if let Some(rest) = o.strip_prefix("bfc ")
        && let Some((reg, imms)) = rest.split_once(", ")
    {
        let zr = if reg.starts_with('w') { "wzr" } else { "xzr" };
        return l == format!("bfi {reg}, {zr}, {imms}");
    }
    // Arm prefers SXTL/UXTL for a shift of 0.
    for (a, b) in [
        ("sxtl ", "sshll "),
        ("uxtl ", "ushll "),
        ("sxtl2 ", "sshll2 "),
        ("uxtl2 ", "ushll2 "),
    ] {
        if let Some(rest) = o.strip_prefix(a) {
            return l == format!("{b}{rest}, #0");
        }
    }
    // Optional zero index or offset that llvm-mc spells out.
    if o.starts_with("pmov ") || o.starts_with("ldraa ") || o.starts_with("ldrab ") {
        return l.replace("[0]", "").replace(", #0]!", "]!") == o;
    }
    // BTI without targets; DSB #12, which llvm-mc names DFB; SUBPS with XZR.
    if (o, l) == ("bti", "bti r") || (o, l) == ("dsb #12", "dfb") {
        return true;
    }
    if let Some(rest) = o.strip_prefix("cmpp ") {
        return l == format!("subps xzr, {rest}");
    }
    false
}

/// A SYS alias with a register for an operation that reads none (TLBI
/// ALLE1, IC IALLU, GIC CDEOI): Arm's template `<op> <name>{, <Xt>}` shows
/// it, llvm-mc falls back to SYS. Accepted when llvm-mc's SYS fields are the
/// word's, the register is the same, and the same operation with Rt 31 is
/// our alias without a register (we treat it as reading none; llvm-mc agrees
/// on Rt 31 words, which the corpus compares as "same").
fn register_on_no_input_op(w: u32, o: &str, l: &str) -> bool {
    if w & 0xfff8_0000 != 0xd508_0000 || w & 0x1f == 0x1f {
        return false;
    }
    let reg = format!(", x{}", w & 0x1f);
    let sys = format!(
        "sys #{}, c{}, c{}, #{}{reg}",
        (w >> 16) & 7,
        (w >> 12) & 15,
        (w >> 8) & 15,
        (w >> 5) & 7
    );
    let Some(name) = o.strip_suffix(&reg) else {
        return false;
    };
    l == sys
        && !o.starts_with("sys ")
        && ours(w | 0x1f).map(|t| norm_ours(&t)).as_deref() == Some(name)
}

/// The system-register operand of a system move. Ours must be the
/// specification's name for the encoding (the other direction's for a
/// register defined only for reads or only for writes), or the generic
/// `sN_N_cN_cN_N` where it names none. llvm-mc may differ only by a name the
/// specification does not have (ETMv4's `trcoslar`, the unindexed
/// `trcextinselr`) or by the generic form for one it has (a register newer
/// than LLVM, a write to a read-only register). Nothing else may differ.
fn sysreg_name(w: u32, o: &str, l: &str) -> bool {
    let a: Vec<&str> = o.split(' ').collect();
    let b: Vec<&str> = l.split(' ').collect();
    if a.len() != b.len() || !matches!(a[0], "mrs" | "msr" | "mrrs" | "msrr") {
        return false;
    }
    let diff: Vec<(&str, &str)> = a
        .iter()
        .zip(&b)
        .filter(|(x, y)| x != y)
        .map(|(x, y)| (*x, *y))
        .collect();
    let [(x, y)] = diff[..] else { return false };
    let (x, y) = (x.trim_end_matches(','), y.trim_end_matches(','));
    let enc = ((w >> 5) & 0xffff) as u16;
    let write = w & 1 << 21 == 0;
    let generic = format!(
        "s{}_{}_c{}_c{}_{}",
        (enc >> 14) & 3,
        (enc >> 11) & 7,
        (enc >> 7) & 15,
        (enc >> 3) & 15,
        enc & 7
    );
    let spec = system_register(enc, write).or_else(|| system_register(enc, !write));
    if x != spec.unwrap_or(&generic) {
        return false;
    }
    let arm_name = |t: &str| system_register_names().any(|n| n == t);
    !arm_name(y) && y != generic || (y == generic && spec.is_some())
}

/// A word llvm-mc decodes with a "potentially undefined" warning and we
/// reject, because bits Arm fixes differ (FEAT_LSUI `cast`/`caspt`... with
/// `Rt2` other than 11111: Arm's encoding has fixed ones, LLVM treats them as
/// should-be bits). Setting those few bits to their fixed values gives
/// llvm-mc's text.
fn soft_checked_fixed_bits(w: u32, infos: &[fg_arch_arm64::EncodingInfo], l: &str) -> bool {
    let l = norm_llvm(l);
    infos.iter().any(|e| {
        let d = (w ^ e.value) & e.mask;
        d != 0 && d.count_ones() <= 6 && ours(w ^ d).is_some_and(|o| norm_ours(&o) == l)
    })
}

/// llvm-mc decodes system-space encodings with op0 = 0 or 1, which Arm leaves
/// unallocated for register moves, as generic MSR/MRS (`s0_...`, `s1_...`).
fn generic_system_space(l: &str) -> bool {
    let words: Vec<&str> = l.split(' ').collect();
    matches!(words.first(), Some(&"msr" | &"msrr" | &"mrs" | &"mrrs"))
        && words
            .iter()
            .any(|w| w.starts_with("s0_") || w.starts_with("s1_"))
}

#[test]
fn agrees_with_llvm_mc() {
    let Some(version) = llvm_version() else {
        eprintln!("note: llvm-mc not found or without AArch64; LLVM oracle skipped");
        return;
    };
    if version < 23 {
        eprintln!(
            "note: llvm-mc {version} predates the 2026 A64 extensions; LLVM oracle skipped (needs 23+)"
        );
        return;
    }

    // Words to compare.
    let mut x = env_num("FULG_A64_ORACLE_SEED", 0x2545_f491_4f6c_dd1d) | 1;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut words: Vec<u32> = (0..env_num("FULG_A64_ORACLE_WORDS", 60_000))
        .map(|_| next() as u32)
        .collect();
    let per = env_num("FULG_A64_ORACLE_PER_ENCODING", 3);
    let infos: Vec<_> = encodings().collect();
    for e in &infos {
        for _ in 0..per {
            words.push(((next() as u32) & !e.mask) | e.value);
        }
    }
    // System instructions, where names come from two specification sources
    // (the XML's SysOp() and Registers.json) and Rt decides the text: every
    // SYS/SYSP operation of CRn 7 to 12 with Rt 0 and 31, every MRS/MSR
    // register encoding with Rt 0.
    for base in [0xd508_0000u32, 0xd548_0000] {
        for op in 0..1u32 << 14 {
            if (7..=12).contains(&((op >> 7) & 15)) {
                words.extend([base | op << 5, base | op << 5 | 31]);
            }
        }
    }
    for base in [0xd510_0000u32, 0xd530_0000] {
        for enc in 0..1u32 << 15 {
            words.push(base | enc << 5);
        }
    }
    words.sort_unstable();
    words.dedup();

    let theirs = llvm(&words);
    let mine: HashMap<u32, Option<String>> = words.iter().map(|&w| (w, ours(w))).collect();
    let should_be: HashMap<&str, (u32, u32)> = infos
        .iter()
        .map(|e| (e.name, (e.should_be_mask, e.should_be_value)))
        .collect();
    let not_decoded: Vec<(u32, u32)> = encodings_not_decoded().map(|(_, m, v)| (m, v)).collect();

    // Words llvm-mc rejects and we decode: the neighbours we may explain them by.
    let extra: Vec<u32> = words
        .iter()
        .copied()
        .filter(|w| !theirs.text.contains_key(w) && mine[w].is_some())
        .collect();
    let fixed: HashMap<u32, u32> = extra
        .iter()
        .filter_map(|&w| {
            let (m, v) = should_be.get(encoding_name(w)?)?;
            (w & m != *v).then_some((w, (w & !m) | v))
        })
        .collect();
    // Ignored bits: clear bits one at a time while our text stays the same.
    let cleared: HashMap<u32, u32> = extra
        .iter()
        .map(|&w| {
            let text = mine[&w].clone();
            let mut c = w;
            for b in 0..32 {
                let t = c & !(1 << b);
                if t != c && ours(t) == text {
                    c = t;
                }
            }
            (w, c)
        })
        .collect();
    let neighbours: Vec<u32> = fixed.values().chain(cleared.values()).copied().collect();
    let theirs_n = llvm(&neighbours);
    let extra_texts: Vec<String> = extra.iter().map(|w| mine[w].clone().unwrap()).collect();
    let unknown: HashSet<u32> = unknown_to_llvm(&extra_texts)
        .into_iter()
        .map(|i| extra[i])
        .collect();

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut bad: Vec<String> = Vec::new();
    for &w in &words {
        let o = mine[&w].as_deref();
        let l = theirs.text.get(&w).map(String::as_str);
        let category = match (o, l) {
            (None, None) => "both invalid",
            (Some(o), Some(l)) => {
                let (o, l) = (norm_ours(o), norm_llvm(l));
                if o == l {
                    "same"
                } else if same_modulo_numbers(&o, &l) {
                    "number spelling"
                } else if alias_choice(&o, &l) {
                    "alias choice"
                } else if sysreg_name(w, &o, &l) {
                    "system register name"
                } else if register_on_no_input_op(w, &o, &l) {
                    "register on a no-input system op"
                } else if l.starts_with("hint #")
                    && unknown_to_llvm(std::slice::from_ref(&o)).contains(&0)
                {
                    "hint newer than llvm"
                } else {
                    bad.push(format!("{w:08x} text: ours `{o}`, llvm `{l}`"));
                    "different"
                }
            }
            (Some(o), None) => {
                let o_n = norm_ours(o);
                let explained_by = |n: Option<&u32>| {
                    n.and_then(|n| theirs_n.text.get(n))
                        .is_some_and(|t| norm_llvm(t) == o_n)
                };
                if is_unpredictable(w) {
                    "unpredictable"
                } else if explained_by(fixed.get(&w)) {
                    "should-be bits"
                } else if cleared[&w] != w && explained_by(cleared.get(&w)) {
                    "ignored bits"
                } else if unknown.contains(&w) {
                    "newer than llvm"
                } else {
                    bad.push(format!("{w:08x} ours `{o}`, llvm rejects"));
                    "different"
                }
            }
            (None, Some(l)) => {
                if not_decoded.iter().any(|&(m, v)| w & m == v) {
                    "newer than the XML"
                } else if generic_system_space(&norm_llvm(l)) {
                    "unallocated system space"
                } else if theirs.soft.contains(&w) && soft_checked_fixed_bits(w, &infos, l) {
                    "fixed bits llvm only soft-checks"
                } else {
                    bad.push(format!("{w:08x} ours rejects, llvm `{l}`"));
                    "different"
                }
            }
        };
        *counts.entry(category).or_default() += 1;
    }
    eprintln!("llvm-mc {version}: {} words", words.len());
    for (k, v) in &counts {
        eprintln!("  {k:28} {v}");
    }
    assert!(
        bad.is_empty(),
        "{} unexplained differences:\n{}",
        bad.len(),
        bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        counts.get("same").copied().unwrap_or(0)
            + counts.get("number spelling").copied().unwrap_or(0)
            > words.len() / 4
    );
}
