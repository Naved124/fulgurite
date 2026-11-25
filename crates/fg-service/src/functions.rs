// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Function recovery for a session: the seed pass and CFG recovery, with each
//! function's confidence, where it came from and why.

use crate::Session;
use fg_analysis::{cfg, seeds};
use fg_core::Va;
use fg_facts::{Bucket, Claim, FactStore, Slot, Status, Verdict};
use fg_ir::Mode;
use serde::Serialize;

/// One recovered function.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionInfo {
    /// Entry address.
    pub entry: Va,
    /// Name, from the file's symbols (aliases resolved to one), or the
    /// listing's label (`puts@plt`).
    pub name: Option<String>,
    /// Basic blocks decoded.
    pub blocks: usize,
    /// Bytes of code in those blocks.
    pub code_bytes: u64,
    /// Who says this is a function.
    pub status: Status,
    /// How sure, and its display bucket.
    pub confidence: f32,
    /// Display bucket of the confidence.
    pub bucket: Bucket,
    /// The pass whose fact decided it (`seeds`, `cfg.calls`, `cfg.unwind`...).
    pub found_by: String,
    /// The reasons, strongest first.
    pub evidence: Vec<String>,
    /// A block ends in an indirect jump not resolved yet.
    pub unresolved_jumps: bool,
    /// Why the function never returns to its caller, if it does not (each way
    /// its paths end); empty if it may return.
    pub no_return: Vec<String>,
}

/// Every function, by entry.
#[derive(Clone, Debug, Serialize)]
pub struct Functions {
    /// The functions.
    pub functions: Vec<FunctionInfo>,
    /// Code ranges that are parts of a function rather than functions:
    /// (start, owning function).
    pub fragments: Vec<(Va, Va)>,
}

/// Why functions could not be recovered.
#[derive(Debug)]
pub enum FunctionsError {
    /// No decoder for this architecture.
    NoDecoder,
    /// A pass failed (a bug: the loader's values are checked).
    Pass(String),
}

impl std::fmt::Display for FunctionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionsError::NoDecoder => write!(f, "no decoder for this architecture"),
            FunctionsError::Pass(e) => write!(f, "analysis failed: {e}"),
        }
    }
}

impl std::error::Error for FunctionsError {}

/// The seed pass and CFG recovery: the facts and the CFG they give.
pub(crate) fn analyse(session: &Session) -> Result<(FactStore, cfg::Cfg), FunctionsError> {
    let arch = session.arch().ok_or(FunctionsError::NoDecoder)?;
    let bin = session.binary();
    let mut store = FactStore::new();
    seeds::add_seed_facts(bin, &mut store).map_err(|e| FunctionsError::Pass(e.to_string()))?;
    let g = cfg::recover(bin, session.bytes(), arch, Mode::Native, &mut store)
        .map_err(|e| FunctionsError::Pass(e.to_string()))?;
    Ok((store, g))
}

pub(crate) fn recover(session: &Session) -> Result<Functions, FunctionsError> {
    let arch = session.arch().ok_or(FunctionsError::NoDecoder)?;
    let (store, g) = analyse(session)?;
    let labels = crate::disasm::code_labels(session, arch);
    let mut functions = Vec::with_capacity(g.functions.len());
    for (&entry, f) in &g.functions {
        let Verdict::Accepted(id) = store.resolve(&Slot::IsFunction { entry }).verdict else {
            continue;
        };
        let Some(fact) = store.get(id) else { continue };
        let mut evidence: Vec<_> = store
            .facts_in(&Slot::IsFunction { entry })
            .flat_map(|f| f.evidence().iter())
            .collect();
        evidence.sort_by_key(|e| std::cmp::Reverse(e.weight));
        let name = match store.resolve(&Slot::Name { entity: entry }).verdict {
            Verdict::Accepted(n) => match store.get(n).map(|f| f.claim()) {
                Some(Claim::Name { name, .. }) => Some(name.clone()),
                _ => None,
            },
            _ => None,
        }
        .or_else(|| labels.get(&entry.0).cloned());
        let no_return = match store.resolve(&Slot::NoReturn { entry }).verdict {
            Verdict::Accepted(n) => store.get(n).map_or_else(Vec::new, |f| {
                f.evidence()
                    .iter()
                    .map(|e| e.evidence.text.clone())
                    .collect()
            }),
            _ => Vec::new(),
        };
        functions.push(FunctionInfo {
            entry,
            name,
            blocks: f.blocks.len(),
            code_bytes: f.blocks.iter().map(|(s, b)| b.end.0 - s.0).sum(),
            status: fact.status(),
            confidence: fact.confidence().value(),
            bucket: fact.confidence().bucket(),
            found_by: fact.provenance().pass.clone(),
            evidence: evidence.iter().map(|e| e.evidence.text.clone()).collect(),
            unresolved_jumps: f.blocks.values().any(|b| b.unresolved),
            no_return,
        });
    }
    Ok(Functions {
        functions,
        fragments: g.fragments.into_iter().collect(),
    })
}
