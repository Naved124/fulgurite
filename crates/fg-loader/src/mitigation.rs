// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Exploit-mitigation verdicts. Every verdict carries the evidence it was based
//! on, so "how was this detected?" always has an answer (design section 6.5).

use fg_core::Evidence;
use serde::Serialize;

/// Outcome of a mitigation check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum Verdict {
    /// The protection is fully in place.
    Enabled,
    /// Partly in place (e.g. partial RELRO).
    Partial,
    /// Not in place.
    Disabled,
    /// Does not apply to this kind of file.
    NotApplicable,
    /// Cannot be decided from what has been parsed.
    Unknown,
}

/// One mitigation check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Mitigation {
    /// Short name, e.g. `NX`.
    pub name: &'static str,
    /// The verdict.
    pub verdict: Verdict,
    /// One-line summary of the verdict.
    pub summary: String,
    /// What was observed.
    pub evidence: Vec<Evidence>,
    /// Plain-language reason this protection matters.
    pub why_it_matters: &'static str,
}

impl Mitigation {
    /// Creates a verdict.
    pub fn new(
        name: &'static str,
        verdict: Verdict,
        summary: impl Into<String>,
        evidence: Vec<Evidence>,
        why_it_matters: &'static str,
    ) -> Mitigation {
        Mitigation {
            name,
            verdict,
            summary: summary.into(),
            evidence,
            why_it_matters,
        }
    }
}

/// All mitigation checks for one binary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MitigationReport {
    /// Position independence (ASLR for the program's own code).
    pub pie: Mitigation,
    /// Non-executable stack.
    pub nx: Mitigation,
    /// Read-only relocations (GOT protection).
    pub relro: Mitigation,
    /// Stack canaries.
    pub canary: Mitigation,
    /// `_FORTIFY_SOURCE` bounds-checked libc calls.
    pub fortify: Mitigation,
    /// Hardware control-flow integrity marking (x86 CET IBT/SHSTK, AArch64 BTI/PAC).
    pub cfi: Mitigation,
    /// Code kept in its own segment, away from data and headers (W^X layout).
    pub separate_code: Mitigation,
    /// Library search paths baked into the file (`RPATH` / `RUNPATH`; PE
    /// `DependentLoadFlags`).
    pub library_paths: Mitigation,
    /// Structured exception handler protection (SafeSEH). Only for formats with
    /// stack-based exception handlers (PE); `None` elsewhere.
    pub seh: Option<Mitigation>,
}

impl MitigationReport {
    /// Creates a report from the checks every format has; the others start as
    /// [`Verdict::Unknown`] and are filled in by the loader that knows them.
    pub fn new(
        pie: Mitigation,
        nx: Mitigation,
        relro: Mitigation,
        canary: Mitigation,
        fortify: Mitigation,
    ) -> Self {
        let unknown =
            |name, why| Mitigation::new(name, Verdict::Unknown, "not checked", Vec::new(), why);
        MitigationReport {
            pie,
            nx,
            relro,
            canary,
            fortify,
            cfi: unknown("CFI", WHY_CFI),
            separate_code: unknown("SepCode", WHY_SEPARATE_CODE),
            library_paths: unknown("LibPath", WHY_LIBRARY_PATHS),
            seh: None,
        }
    }

    /// Adds the SafeSEH check.
    pub fn with_seh(mut self, m: Mitigation) -> Self {
        self.seh = Some(m);
        self
    }

    /// Replaces the CFI check.
    pub fn with_cfi(mut self, m: Mitigation) -> Self {
        self.cfi = m;
        self
    }

    /// Replaces the separate-code check.
    pub fn with_separate_code(mut self, m: Mitigation) -> Self {
        self.separate_code = m;
        self
    }

    /// Replaces the library-path check.
    pub fn with_library_paths(mut self, m: Mitigation) -> Self {
        self.library_paths = m;
        self
    }

    /// All checks in display order.
    ///
    /// Returns a `Vec` rather than a fixed-size array so new checks can be added
    /// without breaking callers.
    pub fn all(&self) -> Vec<&Mitigation> {
        let mut v = vec![
            &self.pie,
            &self.nx,
            &self.relro,
            &self.canary,
            &self.fortify,
            &self.cfi,
            &self.separate_code,
            &self.library_paths,
        ];
        v.extend(self.seh.as_ref());
        v
    }
}

pub(crate) const WHY_PIE: &str = "With ASLR, a PIE's code lands at a random address each run, so exploits cannot hard-code code addresses.";
pub(crate) const WHY_NX: &str = "A non-executable stack stops bytes written to the stack (e.g. shellcode) from running as code.";
pub(crate) const WHY_RELRO: &str = "RELRO makes the GOT read-only after startup, so overwriting a function pointer there no longer hijacks calls.";
pub(crate) const WHY_CANARY: &str = "A random value placed before the return address detects stack buffer overflows before the function returns.";
pub(crate) const WHY_FORTIFY: &str = "FORTIFY_SOURCE swaps calls like memcpy for __memcpy_chk, which abort when a copy would overflow a buffer of known size.";
pub(crate) const WHY_CFI: &str = "Hardware CFI makes indirect jumps land only on marked instructions and checks return addresses against a shadow copy, which breaks ROP and JOP chains.";
pub(crate) const WHY_SEPARATE_CODE: &str = "When only real code is executable, headers and read-only data cannot be used as a source of ROP gadgets, and no page is both writable and executable.";
pub(crate) const WHY_LIBRARY_PATHS: &str = "A search path baked into the binary decides where shared libraries are loaded from; if an attacker can write to one of those directories, they can plant a library that runs their code.";
pub(crate) const WHY_SEH: &str = "SafeSEH lists the program's real exception handlers, so a stack overflow that overwrites an exception-handler pointer cannot redirect execution to arbitrary code.";
