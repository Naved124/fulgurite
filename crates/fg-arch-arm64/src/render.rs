// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Assembler templates to tokens.

use crate::helpers::{decode_bit_masks, fp_imm};
use crate::model::{Dflt, Item, Kind, Op};
use crate::system_register;
use crate::tables::{ITEMS, OPS, VTABLES, cond, value};
use fg_ir::{Token, TokenKind};

/// Why a template could not be printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// An operand value has no spelling here (try the next alternative).
    NoEntry,
    /// The encoding is reserved.
    Reserved,
}

/// The result of rendering a run of items.
struct Part {
    tokens: Vec<Token>,
    /// Number of operands rendered.
    ops: usize,
    /// All of them had their default value.
    all_default: bool,
}

/// Renders the template `ITEMS[start..start + len]` of word `w` at `pc`.
pub(crate) fn render(w: u32, pc: u64, start: u32, len: u16) -> Result<Vec<Token>, Fail> {
    let items = &ITEMS[start as usize..start as usize + len as usize];
    let mut part = run(w, pc, items)?;
    classify_mnemonic(&mut part.tokens);
    Ok(part.tokens)
}

/// Before the first space every token is part of the mnemonic (`b.eq`, `sshll2`).
fn classify_mnemonic(tokens: &mut Vec<Token>) {
    let n = tokens
        .iter()
        .position(|t| t.kind == TokenKind::Space)
        .unwrap_or(tokens.len());
    if n == 0 {
        return;
    }
    let text: String = tokens[..n].iter().map(|t| t.text.as_str()).collect();
    tokens.splice(0..n, [Token::new(TokenKind::Mnemonic, text)]);
}

fn run(w: u32, pc: u64, items: &[Item]) -> Result<Part, Fail> {
    let mut out = Part {
        tokens: Vec::new(),
        ops: 0,
        all_default: true,
    };
    let mut i = 0;
    while i < items.len() {
        match items[i] {
            Item::Text(t) => {
                text(&mut out.tokens, t);
                i += 1;
            }
            Item::Space => {
                out.tokens.push(Token::new(TokenKind::Space, " "));
                i += 1;
            }
            Item::Op(id) => {
                let op = &OPS[id as usize];
                let is_default = operand(w, pc, op, &mut out.tokens)?;
                out.ops += 1;
                out.all_default &= is_default;
                i += 1;
            }
            Item::Opt(n) => {
                let sub = &items[i + 1..i + 1 + n as usize];
                let part = run(w, pc, sub)?;
                // Left out when it says nothing: only operands at their default,
                // or fixed text that is a zero (`, #0`). Fixed words such as
                // `vgx2` stay.
                let says_something = if part.ops > 0 {
                    !part.all_default
                } else {
                    let text: String = part.tokens.iter().map(|t| t.text.as_str()).collect();
                    let numbers: Vec<&str> = text
                        .split(|c: char| !c.is_ascii_digit())
                        .filter(|n| !n.is_empty())
                        .collect();
                    numbers.is_empty()
                        || numbers
                            .iter()
                            .any(|n| !n.trim_start_matches('0').is_empty())
                };
                if says_something {
                    out.tokens.extend(part.tokens);
                    out.ops += part.ops;
                    out.all_default &= part.all_default;
                }
                i += 1 + n as usize;
            }
            Item::Alt(n) => {
                let mut j = i + 1;
                let mut chosen: Option<Part> = None;
                let mut failure = Fail::NoEntry;
                for _ in 0..n {
                    let Item::Branch(len) = items[j] else {
                        unreachable!("Alt without Branch")
                    };
                    let sub = &items[j + 1..j + 1 + len as usize];
                    if chosen.is_none() {
                        match run(w, pc, sub) {
                            Ok(p) => chosen = Some(p),
                            Err(Fail::Reserved) => failure = Fail::Reserved,
                            Err(Fail::NoEntry) => {}
                        }
                    }
                    j += 1 + len as usize;
                }
                let part = chosen.ok_or(failure)?;
                out.tokens.extend(part.tokens);
                out.ops += part.ops;
                out.all_default &= part.all_default;
                i = j;
            }
            Item::Branch(_) => unreachable!("Branch outside Alt"),
        }
    }
    Ok(out)
}

/// Splits fixed text into punctuation and keywords.
fn text(tokens: &mut Vec<Token>, t: &str) {
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if !word.is_empty() {
            tokens.push(Token::new(TokenKind::Keyword, std::mem::take(word)));
        }
    };
    for c in t.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' && !word.is_empty() {
            word.push(c);
        } else {
            flush(&mut word, tokens);
            let kind = if c == ' ' {
                TokenKind::Space
            } else {
                TokenKind::Punct
            };
            tokens.push(Token::new(kind, c.to_string()));
        }
    }
    flush(&mut word, tokens);
}

/// Renders one operand; returns whether it has its default value.
fn operand(w: u32, pc: u64, op: &Op, tokens: &mut Vec<Token>) -> Result<bool, Fail> {
    if op.when != 0 && !cond(op.when, w) {
        return Err(Fail::NoEntry);
    }
    let v = value(op.val, w);
    if let Some((lo, hi)) = op.valid
        && (v < lo || v > hi)
    {
        return Err(Fail::Reserved);
    }
    let is_default = match op.default {
        Dflt::Int(d) => v == d,
        Dflt::IntUnless(d, c) => v == d && !cond(c, w),
        _ => false,
    };
    match op.kind {
        Kind::Reg {
            prefix,
            suffix,
            r31,
        } => {
            let name = match r31 {
                Some(name) if v == 31 => name.to_string(),
                _ => format!("{prefix}{v}{suffix}"),
            };
            tokens.push(Token::new(TokenKind::Register, name));
        }
        Kind::Imm => tokens.push(Token::with_value(
            TokenKind::Number,
            format!("#{v}"),
            v as u64,
        )),
        Kind::Num => tokens.push(Token::with_value(
            TokenKind::Number,
            v.to_string(),
            v as u64,
        )),
        Kind::Hex(hash) => tokens.push(Token::with_value(
            TokenKind::Number,
            format!("{}{v:#x}", if hash { "#" } else { "" }),
            v as u64,
        )),
        Kind::Label => {
            let target = pc.wrapping_add(v as u64);
            tokens.push(Token::with_value(
                TokenKind::Address,
                format!("{target:#x}"),
                target,
            ));
        }
        Kind::Page => {
            let target = (pc & !0xfff).wrapping_add(v as u64);
            tokens.push(Token::with_value(
                TokenKind::Address,
                format!("{target:#x}"),
                target,
            ));
        }
        Kind::Table(t) => {
            let entry = VTABLES[t as usize]
                .iter()
                .find(|e| (v as u32) & e.mask == e.value)
                .ok_or(Fail::NoEntry)?;
            match entry.text {
                Some("#") if entry.value_of != 0xFFFF => {
                    let n = value(entry.value_of, w);
                    tokens.push(Token::with_value(
                        TokenKind::Number,
                        format!("#{n}"),
                        n as u64,
                    ));
                }
                Some(s) => {
                    // "lsl|uxtx": LSL when Rd or Rn is SP (register 31), else the extend.
                    // ("lsl|uxtx|n": only Rn counts, Rd 31 being the zero register.)
                    let parts: Vec<&str> = s.split('|').collect();
                    let s = match parts[..] {
                        [lsl, ext, ref rest @ ..] => {
                            let rd_sp = rest.is_empty() && w & 0x1f == 31;
                            if rd_sp || (w >> 5) & 0x1f == 31 {
                                lsl
                            } else {
                                ext
                            }
                        }
                        _ => s,
                    };
                    if let Dflt::Text(d) = op.default {
                        return table_text(tokens, s).map(|()| s == d);
                    }
                    table_text(tokens, s)?;
                }
                None if entry.value_of != 0xFFFF => {
                    let n = value(entry.value_of, w);
                    tokens.push(Token::with_value(
                        TokenKind::Number,
                        n.to_string(),
                        n as u64,
                    ));
                }
                None => return Err(Fail::Reserved),
            }
        }
        Kind::Bitmask(width) => {
            let v = v as u32;
            let (n, immr, imms) = ((v >> 12) & 1, (v >> 6) & 0x3f, v & 0x3f);
            // Width 0: SVE, where the element size follows from N:imms
            // (the <T> of DUPM and the logical-immediate instructions).
            let (m, width) = match width {
                0 if n == 1 => (64, 64),
                0 if imms & 0x20 == 0 => (64, 32),
                0 if imms & 0x10 == 0 => (64, 16),
                0 => (64, 8),
                w => (u32::from(w), u32::from(w)),
            };
            let mut imm = decode_bit_masks(n, imms, immr, m).ok_or(Fail::Reserved)?;
            if width < 64 {
                imm &= (1u64 << width) - 1;
            }
            tokens.push(Token::with_value(
                TokenKind::Number,
                format!("{imm:#x}"),
                imm,
            ));
        }
        Kind::FpImm => {
            let f = fp_imm(v as u32);
            tokens.push(Token::new(TokenKind::Number, format!("{f:.8}")));
        }
        Kind::SysReg(write) => {
            let enc = v as u16;
            // The name for this direction; else the register's name for the
            // other one (an MSR to a read-only register such as
            // ICC_PPI_HMR0_EL1 still names it: the write is UNDEFINED, but
            // the target is known). Encodings named in both directions
            // (DBGDTRRX_EL0 / DBGDTRTX_EL0) keep their own.
            let name = match system_register(enc, write).or_else(|| system_register(enc, !write)) {
                Some(n) => n.to_string(),
                None => format!(
                    "s{}_{}_c{}_c{}_{}",
                    (enc >> 14) & 3,
                    (enc >> 11) & 7,
                    (enc >> 7) & 15,
                    (enc >> 3) & 15,
                    enc & 7
                ),
            };
            tokens.push(Token::new(TokenKind::Register, name));
        }
        Kind::Flag(t) => {
            if v != 0 {
                text(tokens, t);
            }
        }
        Kind::Const(t) => text(tokens, t),
        Kind::ZaMask => za_mask(v as u32, tokens),
    }
    Ok(is_default)
}

/// Text from a value table: `, lsl #12` becomes punctuation, keyword, number.
fn table_text(tokens: &mut Vec<Token>, s: &str) -> Result<(), Fail> {
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        let len = match c {
            ' ' => {
                tokens.push(Token::new(TokenKind::Space, " "));
                1
            }
            ',' | '{' | '}' | '[' | ']' => {
                tokens.push(Token::new(TokenKind::Punct, c.to_string()));
                1
            }
            _ => {
                let end = rest
                    .find([' ', ',', '{', '}', '[', ']'])
                    .unwrap_or(rest.len());
                let word = &rest[..end];
                match word.strip_prefix('#').and_then(|n| n.parse::<i64>().ok()) {
                    Some(n) => tokens.push(Token::with_value(TokenKind::Number, word, n as u64)),
                    None => tokens.push(Token::new(TokenKind::Keyword, word)),
                }
                end
            }
        };
        rest = &rest[len..];
    }
    Ok(())
}

/// SME `ZERO {mask}` (the template has the braces): the 64-bit tiles named by
/// `imm8`, printed with the largest tiles that cover them exactly.
fn za_mask(m: u32, tokens: &mut Vec<Token>) {
    let names = za_tiles(m);
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            tokens.push(Token::new(TokenKind::Punct, ","));
            tokens.push(Token::new(TokenKind::Space, " "));
        }
        tokens.push(Token::new(TokenKind::Register, n.clone()));
    }
}

fn za_tiles(m: u32) -> Vec<String> {
    // One element size for the whole list, the largest whose tiles make up
    // the mask exactly: ZA, then ZAn.H (0x55, 0xaa), then ZAn.S (tiles n and
    // n+4), else the 64-bit tiles.
    if m == 0xff {
        return vec!["za".into()];
    }
    if m == 0x55 || m == 0xaa {
        return vec![format!("za{}.h", u32::from(m == 0xaa))];
    }
    if (0..4).all(|s| (m >> s) & 1 == (m >> (s + 4)) & 1) {
        return (0..4)
            .filter(|s| m >> s & 1 != 0)
            .map(|s| format!("za{s}.s"))
            .collect();
    }
    (0..8)
        .filter(|d| m >> d & 1 != 0)
        .map(|d| format!("za{d}.d"))
        .collect()
}
