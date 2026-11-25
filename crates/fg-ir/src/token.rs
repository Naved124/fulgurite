// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Display tokens. Instructions are rendered as typed tokens rather than plain
//! strings so front ends can colour them, link addresses and registers, and
//! substitute names without re-parsing text.

use serde::Serialize;

/// Assembly syntax.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Syntax {
    /// Intel syntax (destination first), as `objdump -M intel` prints it.
    #[default]
    Intel,
    /// AT&T syntax (source first, `%` registers), as GNU tools print it by default.
    Att,
}

/// What a token is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenKind {
    /// Instruction prefix written as a word (`lock`, `rep`, `bnd`, `notrack`...).
    Prefix,
    /// The mnemonic.
    Mnemonic,
    /// A register name.
    Register,
    /// An immediate or displacement.
    Number,
    /// An address the instruction refers to (branch target, absolute memory address).
    Address,
    /// A keyword such as `qword ptr` or a size suffix.
    Keyword,
    /// Punctuation: `,`, `[`, `]`, `+`, `:`, `*`, `(`, `)`, `$`.
    Punct,
    /// Spacing between parts.
    Space,
    /// A decorator such as an AVX-512 mask `{k1}`, `{z}` or rounding mode.
    Decorator,
    /// A name substituted for an address (added by the listing, not the decoder).
    Symbol,
    /// A trailing comment (added by the listing).
    Comment,
}

/// One display token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// Its text.
    pub text: String,
    /// The numeric value of a [`TokenKind::Number`] or [`TokenKind::Address`] token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
}

impl Token {
    /// Creates a token without a value.
    pub fn new(kind: TokenKind, text: impl Into<String>) -> Token {
        Token {
            kind,
            text: text.into(),
            value: None,
        }
    }

    /// Creates a token carrying a numeric value.
    pub fn with_value(kind: TokenKind, text: impl Into<String>, value: u64) -> Token {
        Token {
            kind,
            text: text.into(),
            value: Some(value),
        }
    }
}

/// Concatenates the text of `tokens`.
pub fn tokens_text(tokens: &[Token]) -> String {
    tokens.iter().map(|t| t.text.as_str()).collect()
}
