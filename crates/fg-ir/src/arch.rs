//! The [`Arch`] trait: what an architecture module provides to the rest of
//! Fulgurite.

use crate::effect::{Effect, RegPart};
use crate::insn::{DecodeError, Insn, Mode};
use crate::token::{Syntax, Token};
use fg_core::{ArchId, Va};

/// One architecture (or one family in one default mode, e.g. x86-64).
///
/// Decoding and formatting are separate: [`Arch::decode`] produces the neutral
/// facts every analysis needs (length, control flow, statically known memory
/// addresses), and [`Arch::format`] renders the same bytes as text tokens on
/// demand, so listings never store strings. M2 adds `lift`, the single source of
/// instruction semantics.
pub trait Arch: Send + Sync {
    /// Which architecture this is.
    fn id(&self) -> ArchId;

    /// Longest valid instruction in bytes (x86: 15, AArch64: 4).
    fn max_insn_len(&self) -> usize;

    /// Alignment every instruction starts on (x86: 1, AArch64: 4).
    fn insn_alignment(&self) -> u64;

    /// Decodes one instruction from the start of `bytes`, which is mapped at `va`.
    /// `bytes` may be longer than the instruction; only its prefix is used.
    fn decode(&self, bytes: &[u8], va: Va, mode: Mode) -> Result<Insn, DecodeError>;

    /// Renders an instruction this module decoded as display tokens.
    fn format(&self, insn: &Insn, syntax: Syntax) -> Vec<Token>;

    /// What an instruction this module decoded does to registers and flags.
    /// Computed on demand: few instructions are ever asked. The default knows
    /// nothing.
    fn effect(&self, _insn: &Insn) -> Effect {
        Effect::UNKNOWN
    }

    /// The registers a called function preserves under the platform's calling
    /// convention (`windows`: Microsoft's, otherwise the System V or AAPCS
    /// one), the stack pointer included.
    fn callee_saved(&self, _windows: bool) -> Vec<crate::effect::Reg> {
        Vec::new()
    }

    /// The register that holds the stack pointer.
    fn stack_pointer(&self) -> Option<crate::effect::Reg> {
        None
    }

    /// The address of the instruction's explicit memory operand, whatever
    /// it does there (a store's included): base, index and displacement, a
    /// PC-relative address already resolved; and what the instruction does
    /// there. `None` without one, or for one not described (segment-based,
    /// a vector of addresses).
    fn mem_addr(&self, _insn: &Insn) -> Option<(crate::effect::Addr, crate::insn::Access)> {
        None
    }

    /// True if code builds addresses from two instructions (AArch64 `adrp` +
    /// `add`), so finding the addresses it takes needs [`Arch::effect`].
    fn address_pairs(&self) -> bool {
        false
    }

    /// The name of a register's low bits, as listings write it.
    fn reg_name(&self, r: RegPart) -> String {
        format!("r{}.{}", r.reg.0, r.bits)
    }
}
