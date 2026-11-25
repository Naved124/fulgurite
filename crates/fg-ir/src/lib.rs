// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Fulgurite's intermediate representation.
//!
//! Today this crate holds the architecture-neutral view of a decoded machine
//! instruction ([`Insn`]) and the [`Arch`] trait that every architecture module
//! implements. Everything above the decoders (CFG recovery, the listing, the CLI)
//! works with these types only, so adding an architecture never touches them.
//! The lifted IR tiers (LIR, MIR, HIR) join this crate in M2, together with the
//! `lift` method of [`Arch`].

pub mod arch;
pub mod effect;
pub mod insn;
pub mod token;

pub use arch::Arch;
pub use effect::{Addr, BinOp, Cond, Effect, Flags, Index, Reg, RegPart, Value};
pub use insn::{Access, DecodeError, Flow, Insn, InsnBytes, MemRef, Mode};
pub use token::{Syntax, Token, TokenKind, tokens_text};
