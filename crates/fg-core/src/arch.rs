//! Architecture identifiers. Recognising an architecture does not mean it can be
//! decoded yet; decoding support lives in the `fg-arch-*` crates.

use serde::Serialize;
use std::fmt;

/// A CPU architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum ArchId {
    /// 32-bit x86.
    X86,
    /// x86-64 / AMD64.
    X86_64,
    /// 32-bit Arm.
    Arm,
    /// 64-bit Arm (AArch64 / ARM64).
    Aarch64,
    /// RISC-V.
    RiscV,
    /// Recognised format, unrecognised machine.
    Unknown,
}

impl ArchId {
    /// Short display name.
    pub fn name(self) -> &'static str {
        match self {
            ArchId::X86 => "x86",
            ArchId::X86_64 => "x86-64",
            ArchId::Arm => "ARM",
            ArchId::Aarch64 => "AArch64",
            ArchId::RiscV => "RISC-V",
            ArchId::Unknown => "unknown",
        }
    }

    /// Whether the v1 analysis engine targets this architecture.
    pub fn is_v1_target(self) -> bool {
        matches!(self, ArchId::X86_64 | ArchId::Aarch64)
    }
}

impl fmt::Display for ArchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Native word size of a binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Bitness {
    /// 32-bit addresses.
    Bits32,
    /// 64-bit addresses.
    Bits64,
}

impl Bitness {
    /// Size of an address in bytes.
    pub fn word_size(self) -> u8 {
        match self {
            Bitness::Bits32 => 4,
            Bitness::Bits64 => 8,
        }
    }
}
