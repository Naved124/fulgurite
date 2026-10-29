//! Binary loaders.
//!
//! A loader (ELF or PE) turns raw, untrusted bytes into a [`LoadedBinary`]: a format-neutral
//! description of the program (architecture, memory segments, entry point,
//! mitigations) plus the format-specific details in [`FormatMetadata`].
//!
//! Design rules (see the design document, section 6):
//! * Loaders never panic on bad input. Problems become [`fg_core::Anomaly`]s.
//! * What the OS loader would do (segments) is authoritative; metadata that the
//!   OS ignores (section names) is advisory.
//! * Every reported value keeps the file bytes it came from.

pub mod elf;
mod error;
pub mod mitigation;
mod model;
pub mod pe;

pub use error::LoadError;
pub use mitigation::{Mitigation, MitigationReport, Verdict};
pub use model::{
    BinaryKind, Format, FormatMetadata, Limits, LoadOptions, LoadedBinary, RelocKind, Relocation,
    Section, Seed, SeedKind, Segment, Symbol, SymbolBinding, SymbolKind, SymbolRef, SymbolTable,
    SymbolVersion,
};

/// Identifies the container format of `bytes` from its magic number, if known.
pub fn detect(bytes: &[u8]) -> Option<Format> {
    if elf::is_elf(bytes) {
        Some(Format::Elf)
    } else if pe::is_pe(bytes) {
        Some(Format::Pe)
    } else {
        None
    }
}

/// Loads `bytes` with the loader for its detected format.
pub fn load(bytes: &[u8], options: &LoadOptions) -> Result<LoadedBinary, LoadError> {
    match detect(bytes) {
        Some(Format::Elf) => elf::load(bytes, options),
        Some(Format::Pe) => pe::load(bytes, options),
        _ => Err(LoadError::NotRecognized {
            magic: bytes.iter().take(4).copied().collect(),
        }),
    }
}
