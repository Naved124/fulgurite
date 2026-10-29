//! The architecture-neutral view of one decoded instruction.

use fg_core::Va;
use serde::{Serialize, Serializer};
use std::fmt;

/// Decoding mode. Most callers pass [`Mode::Native`], the architecture's own
/// default; the others exist for code that switches modes (32-bit code inside a
/// 64-bit image, 16-bit boot code, Thumb later).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Mode {
    /// The architecture's default mode.
    #[default]
    Native,
    /// x86 real / 16-bit protected mode.
    X86_16,
    /// x86 32-bit protected mode.
    X86_32,
    /// x86 64-bit long mode.
    X86_64,
}

/// The raw bytes of one instruction (at most 16).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InsnBytes {
    buf: [u8; InsnBytes::CAPACITY],
    len: u8,
}

impl InsnBytes {
    /// Most bytes an instruction can have on any supported architecture.
    pub const CAPACITY: usize = 16;

    /// Copies up to [`InsnBytes::CAPACITY`] bytes from `bytes`.
    pub fn new(bytes: &[u8]) -> InsnBytes {
        let len = bytes.len().min(Self::CAPACITY);
        let mut buf = [0; Self::CAPACITY];
        buf[..len].copy_from_slice(&bytes[..len]);
        InsnBytes {
            buf,
            len: len as u8,
        }
    }

    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }
}

impl fmt::Debug for InsnBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.as_slice().iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for InsnBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.as_slice().iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }
}

/// Where control goes after an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Flow {
    /// Continues with the next instruction.
    Next,
    /// Unconditional direct jump.
    Jump {
        /// Destination.
        target: Va,
    },
    /// Conditional direct branch; falls through when not taken.
    Branch {
        /// Destination when taken.
        target: Va,
    },
    /// Direct call; normally returns to the next instruction.
    Call {
        /// Called address.
        target: Va,
    },
    /// Jump through a register or memory (switch tables, tail calls, PLT/IAT stubs).
    IndirectJump,
    /// Call through a register or memory (imports, virtual calls, function pointers).
    IndirectCall,
    /// Return to the caller.
    Return,
    /// Software interrupt or system call (`int`, `int3`, `syscall`...); execution
    /// usually resumes at the next instruction.
    Interrupt,
    /// Always faults (`ud2`, ...): nothing follows on this path.
    Trap,
}

impl Flow {
    /// True if execution can continue with the next instruction.
    pub fn falls_through(self) -> bool {
        matches!(
            self,
            Flow::Next
                | Flow::Branch { .. }
                | Flow::Call { .. }
                | Flow::IndirectCall
                | Flow::Interrupt
        )
    }

    /// The statically known destination of a direct jump, branch or call.
    pub fn target(self) -> Option<Va> {
        match self {
            Flow::Jump { target } | Flow::Branch { target } | Flow::Call { target } => Some(target),
            _ => None,
        }
    }

    /// True for direct and indirect calls.
    pub fn is_call(self) -> bool {
        matches!(self, Flow::Call { .. } | Flow::IndirectCall)
    }

    /// True if the instruction ends a basic block.
    pub fn ends_block(self) -> bool {
        !matches!(self, Flow::Next | Flow::Call { .. } | Flow::IndirectCall)
    }
}

/// How an instruction uses its memory operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Access {
    /// Only the address is computed (`lea`, multi-byte `nop`, prefetch hints).
    Address,
    /// Read.
    Read,
    /// Written.
    Write,
    /// Read and written.
    ReadWrite,
}

/// The explicit memory operand of an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct MemRef {
    /// The address, when it does not depend on registers: PC-relative operands
    /// (`[rip + 0x2f1a]`) and absolute ones (`[0x404028]`). `None` for
    /// register-based and segment-based (`fs:`, `gs:`) operands.
    pub addr: Option<Va>,
    /// True if the address is relative to the instruction pointer.
    pub pc_relative: bool,
    /// True if a segment override with a non-zero base applies (`fs:` / `gs:`
    /// in 64-bit code), so the value is an offset, not an address.
    pub segment_based: bool,
    /// The displacement as encoded (sign-extended).
    pub displacement: i64,
    /// Bytes accessed (0 if not a plain size, e.g. `fxsave`).
    pub size: u32,
    /// How the operand is used.
    pub access: Access,
    /// True if the access may not happen (`cmov`, masked vector stores).
    pub conditional: bool,
}

/// One decoded instruction, without its text. [`crate::Arch::format`] renders it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct Insn {
    /// Address of the first byte.
    pub va: Va,
    /// The instruction's bytes.
    pub bytes: InsnBytes,
    /// Mode it was decoded in.
    pub mode: Mode,
    /// Control flow.
    pub flow: Flow,
    /// Explicit memory operand, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<MemRef>,
    /// First immediate operand, at its operand size (a sign-extended `imm8` in
    /// a 32-bit instruction is extended to 32 bits, not 64), if any.
    /// Absolute addresses in non-PIC code usually arrive this way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imm: Option<u64>,
    /// True for instructions that do nothing (`nop`, `xchg ax, ax`...). Compilers
    /// use them as padding between functions.
    pub nop: bool,
}

impl Insn {
    /// Creates an instruction description.
    pub fn new(
        va: Va,
        bytes: &[u8],
        mode: Mode,
        flow: Flow,
        mem: Option<MemRef>,
        imm: Option<u64>,
        nop: bool,
    ) -> Insn {
        Insn {
            va,
            bytes: InsnBytes::new(bytes),
            mode,
            flow,
            mem,
            imm,
            nop,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> u64 {
        self.bytes.as_slice().len() as u64
    }

    /// Always false: an instruction has at least one byte. Present for API symmetry.
    pub fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }

    /// Address just past the instruction.
    pub fn end(&self) -> Va {
        Va(self.va.0.wrapping_add(self.len()))
    }
}

impl MemRef {
    /// Creates a memory operand description.
    pub fn new(
        addr: Option<Va>,
        pc_relative: bool,
        segment_based: bool,
        displacement: i64,
        size: u32,
        access: Access,
        conditional: bool,
    ) -> MemRef {
        MemRef {
            addr,
            pc_relative,
            segment_based,
            displacement,
            size,
            access,
            conditional,
        }
    }
}

/// Why bytes did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecodeError {
    /// The bytes end before the instruction does.
    Truncated,
    /// Not a valid instruction in this mode. `len` is how many bytes the decoder
    /// examined (at least 1), useful to show how far the attempt got.
    Invalid {
        /// Bytes examined.
        len: u8,
    },
    /// The architecture does not support the requested mode.
    UnsupportedMode,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("instruction runs past the end of the bytes"),
            DecodeError::Invalid { .. } => f.write_str("invalid instruction"),
            DecodeError::UnsupportedMode => f.write_str("mode not supported by this architecture"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_keep_their_length_and_print_as_hex() {
        let b = InsnBytes::new(&[0x48, 0x89, 0xe5]);
        assert_eq!(b.as_slice(), &[0x48, 0x89, 0xe5]);
        assert_eq!(format!("{b:?}"), "48 89 e5");
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"4889e5\"");
    }

    #[test]
    fn flow_classification() {
        let t = Va(0x10);
        assert!(Flow::Branch { target: t }.falls_through());
        assert!(!Flow::Jump { target: t }.falls_through());
        assert!(!Flow::Trap.falls_through());
        assert!(Flow::Call { target: t }.is_call());
        assert!(!Flow::Call { target: t }.ends_block());
        assert!(Flow::IndirectJump.ends_block());
        assert_eq!(Flow::Branch { target: t }.target(), Some(t));
        assert_eq!(Flow::IndirectCall.target(), None);
    }
}
