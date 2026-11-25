// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! The fact: one claim about the program, with who made it, how sure it is, and
//! why (design document, sections 4.2 and 4.3).

use crate::confidence::Confidence;
use fg_core::{Evidence, Va};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The kind of a control-flow edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Execution falls through to the next instruction.
    Fall,
    /// Unconditional jump inside the function.
    Jump,
    /// Conditional branch, taken.
    CondTaken,
    /// Conditional branch, not taken.
    CondNotTaken,
    /// Call.
    Call,
    /// Jump to another function's entry with the stack as on entry.
    TailCall,
    /// Indirect jump or call target (jump table, pointer).
    Indirect,
}

/// What a fact says. Ranges are half-open, `[start, end)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Claim {
    /// The bytes are instructions.
    IsCode {
        /// First byte.
        start: Va,
        /// One past the last byte.
        end: Va,
    },
    /// The bytes are data.
    IsData {
        /// First byte.
        start: Va,
        /// One past the last byte.
        end: Va,
    },
    /// A function starts here.
    IsFunction {
        /// Entry address.
        entry: Va,
    },
    /// The function starting at `entry` has a block ending at `end` (exclusive)
    /// that leaves the function. A function can have several.
    FunctionEnd {
        /// Entry address of the function.
        entry: Va,
        /// One past the last byte of the exiting block.
        end: Va,
    },
    /// Control can flow from the instruction at `from` to `to`.
    Edge {
        /// Address of the instruction that transfers control.
        from: Va,
        /// Target address.
        to: Va,
        /// How.
        edge: EdgeKind,
    },
    /// The function starting at `entry` never returns to its caller.
    NoReturn {
        /// Entry address.
        entry: Va,
    },
    /// The entity at `entity` (function or global) is called `name`.
    Name {
        /// Address of the named entity.
        entity: Va,
        /// The name.
        name: String,
    },
}

/// The question a claim answers. Facts with the same slot compete in resolution
/// (section 4.4): a name slot holds one value, so `Name(f, "a")` and
/// `Name(f, "b")` are rivals; every other kind is a yes/no question, so its
/// slot is the claim itself and only a rejection competes with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Slot {
    /// See [`Claim::IsCode`].
    IsCode {
        /// First byte.
        start: Va,
        /// One past the last byte.
        end: Va,
    },
    /// See [`Claim::IsData`].
    IsData {
        /// First byte.
        start: Va,
        /// One past the last byte.
        end: Va,
    },
    /// See [`Claim::IsFunction`].
    IsFunction {
        /// Entry address.
        entry: Va,
    },
    /// See [`Claim::FunctionEnd`].
    FunctionEnd {
        /// Entry address.
        entry: Va,
        /// End address.
        end: Va,
    },
    /// See [`Claim::Edge`].
    Edge {
        /// Source.
        from: Va,
        /// Target.
        to: Va,
        /// How.
        edge: EdgeKind,
    },
    /// See [`Claim::NoReturn`].
    NoReturn {
        /// Entry address.
        entry: Va,
    },
    /// The name of the entity at this address.
    Name {
        /// Address of the named entity.
        entity: Va,
    },
}

impl Claim {
    /// The question this claim answers.
    pub fn slot(&self) -> Slot {
        match *self {
            Claim::IsCode { start, end } => Slot::IsCode { start, end },
            Claim::IsData { start, end } => Slot::IsData { start, end },
            Claim::IsFunction { entry } => Slot::IsFunction { entry },
            Claim::FunctionEnd { entry, end } => Slot::FunctionEnd { entry, end },
            Claim::Edge { from, to, edge } => Slot::Edge { from, to, edge },
            Claim::NoReturn { entry } => Slot::NoReturn { entry },
            Claim::Name { entity, .. } => Slot::Name { entity },
        }
    }

    /// Canonical bytes: a tag, then every field in order, integers little-endian,
    /// strings length-prefixed. Two claims are equal exactly when these are.
    fn encode(&self, out: &mut Vec<u8>) {
        let va = |out: &mut Vec<u8>, v: Va| out.extend_from_slice(&v.0.to_le_bytes());
        match self {
            Claim::IsCode { start, end } => {
                out.push(1);
                va(out, *start);
                va(out, *end);
            }
            Claim::IsData { start, end } => {
                out.push(2);
                va(out, *start);
                va(out, *end);
            }
            Claim::IsFunction { entry } => {
                out.push(3);
                va(out, *entry);
            }
            Claim::FunctionEnd { entry, end } => {
                out.push(4);
                va(out, *entry);
                va(out, *end);
            }
            Claim::Edge { from, to, edge } => {
                out.push(5);
                va(out, *from);
                va(out, *to);
                out.push(*edge as u8);
            }
            Claim::NoReturn { entry } => {
                out.push(6);
                va(out, *entry);
            }
            Claim::Name { entity, name } => {
                out.push(7);
                va(out, *entity);
                encode_str(out, name);
            }
        }
    }
}

fn encode_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Where a fact comes from, highest authority first in resolution (section 4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// From an analysis pass.
    Inferred,
    /// From format metadata: headers, symbol tables, unwind tables, exports.
    Declared,
    /// From an execution trace or a debugger.
    Observed,
    /// A human set it.
    User,
    /// A human said "no". Suppresses this exact claim, whatever produced it.
    Rejected,
}

/// What kind of observation a piece of evidence is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A field of the file format (entry point, unwind entry, relocation...).
    Format,
    /// A symbol table entry or export.
    Symbol,
    /// Debug information.
    Dwarf,
    /// Control flow reaching the address (a call, a branch, a fall-through).
    Flow,
    /// A byte or instruction pattern with known false positives.
    Pattern,
    /// An argument passed to a known API.
    ApiArgument,
    /// How memory is accessed.
    AccessPattern,
    /// A library signature match.
    Signature,
    /// Executed in a recorded trace.
    TraceHit,
    /// A human decision.
    User,
    /// A suggestion from an AI model, never more than a hint.
    AiSuggestion,
}

/// One reason behind a fact, and how much it contributes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Support {
    /// What kind of observation.
    pub kind: EvidenceKind,
    /// The reason in words, and the file bytes it was read from, if any.
    pub evidence: Evidence,
    /// The address to jump to when the reason is clicked.
    pub anchor: Option<Va>,
    /// Contribution to the fact's confidence.
    pub weight: Confidence,
}

impl Support {
    /// A reason with no address anchor.
    pub fn new(kind: EvidenceKind, evidence: Evidence, weight: Confidence) -> Support {
        Support {
            kind,
            evidence,
            anchor: None,
            weight,
        }
    }

    /// The same reason, anchored at `va`.
    pub fn at(mut self, va: Va) -> Support {
        self.anchor = Some(va);
        self
    }
}

/// Stable identity of a fact: a 128-bit hash of the claim and the pass that
/// made it. The same pass re-deriving the same claim gets the same id, so a
/// re-run updates the fact instead of duplicating it.
/// Written as 32 hex digits, so readers without 128-bit integers keep it exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactId(pub u128);

impl Serialize for FactId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FactId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<FactId, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for FactId {
    type Err = String;

    /// Exactly 32 hex digits.
    fn from_str(s: &str) -> Result<FactId, String> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("fact id {s:?} is not 32 hex digits"));
        }
        u128::from_str_radix(s, 16)
            .map(FactId)
            .map_err(|e| e.to_string())
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// Which pass made a fact, and from what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Pass name, e.g. `seeds.elf_symbols`.
    pub pass: String,
    /// Bumped when the pass's logic changes, so stale results can be found.
    pub pass_version: u32,
    /// Facts this one was derived from.
    pub inputs: Vec<FactId>,
    /// Instructions the pass looked at.
    pub insns: Vec<Va>,
}

impl Provenance {
    /// A pass with no input facts.
    pub fn new(pass: impl Into<String>, pass_version: u32) -> Provenance {
        Provenance {
            pass: pass.into(),
            pass_version,
            inputs: Vec::new(),
            insns: Vec::new(),
        }
    }
}

/// Why a fact could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactError {
    /// A range with `start >= end`.
    EmptyRange,
    /// A name that is empty or contains a control character.
    BadName,
    /// An empty pass name.
    NoPass,
    /// No evidence: every fact must say why it exists.
    NoEvidence,
    /// A user, rejected or observed fact with confidence below 1.0.
    NotCertain(Status),
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FactError::EmptyRange => write!(f, "the range is empty"),
            FactError::BadName => write!(f, "the name is empty or contains a control character"),
            FactError::NoPass => write!(f, "the pass name is empty"),
            FactError::NoEvidence => write!(f, "the fact has no evidence"),
            FactError::NotCertain(s) => write!(f, "a {s:?} fact must have confidence 1.0"),
        }
    }
}

impl std::error::Error for FactError {}

/// One claim about the program. Built only through [`Fact::new`], so every fact
/// in the store has evidence, a valid claim and a status-consistent confidence.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Fact {
    id: FactId,
    claim: Claim,
    status: Status,
    confidence: Confidence,
    provenance: Provenance,
    evidence: Vec<Support>,
}

impl Fact {
    /// Validates and builds a fact.
    pub fn new(
        claim: Claim,
        status: Status,
        confidence: Confidence,
        provenance: Provenance,
        evidence: Vec<Support>,
    ) -> Result<Fact, FactError> {
        match &claim {
            Claim::IsCode { start, end }
            | Claim::IsData { start, end }
            | Claim::FunctionEnd { entry: start, end }
                if start >= end =>
            {
                return Err(FactError::EmptyRange);
            }
            Claim::Name { name, .. } if name.is_empty() || name.chars().any(char::is_control) => {
                return Err(FactError::BadName);
            }
            _ => {}
        }
        if provenance.pass.is_empty() {
            return Err(FactError::NoPass);
        }
        if evidence.is_empty() {
            return Err(FactError::NoEvidence);
        }
        if matches!(status, Status::User | Status::Rejected | Status::Observed)
            && confidence != Confidence::CERTAIN
        {
            return Err(FactError::NotCertain(status));
        }
        let id = fact_id(&claim, &provenance.pass);
        Ok(Fact {
            id,
            claim,
            status,
            confidence,
            provenance,
            evidence,
        })
    }

    /// Stable identity.
    pub fn id(&self) -> FactId {
        self.id
    }

    /// What it says.
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Who said it.
    pub fn status(&self) -> Status {
        self.status
    }

    /// How sure.
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Which pass, from which facts.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Why.
    pub fn evidence(&self) -> &[Support] {
        &self.evidence
    }
}

/// FNV-1a, 128-bit, over the canonical claim bytes and the pass name. Written
/// out rather than taken from `std`, whose hashers may change between releases;
/// ids are stored on disk and must not.
fn fact_id(claim: &Claim, pass: &str) -> FactId {
    const OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
    const PRIME: u128 = 0x0000000001000000000000000000013b;
    let mut bytes = Vec::with_capacity(64);
    claim.encode(&mut bytes);
    encode_str(&mut bytes, pass);
    let mut h = OFFSET;
    for b in bytes {
        h ^= u128::from(b);
        h = h.wrapping_mul(PRIME);
    }
    FactId(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> Vec<Support> {
        vec![Support::new(
            EvidenceKind::Symbol,
            Evidence::new("symbol main"),
            Confidence::CERTAIN,
        )]
    }

    #[test]
    fn fnv_128_matches_the_reference_value() {
        // FNV-1a 128 of the empty input is the offset basis; of "a" it is the
        // published test vector.
        let mut h: u128 = 0x6c62272e07bb014262b821756295c58d;
        h ^= u128::from(b'a');
        h = h.wrapping_mul(0x0000000001000000000000000000013b);
        assert_eq!(h, 0xd228cb696f1a8caf78912b704e4a8964);
    }

    #[test]
    fn ids_are_stable_and_distinguish_claim_and_pass() {
        let f = |c: Claim, p: &str| {
            Fact::new(
                c,
                Status::Declared,
                Confidence::CERTAIN,
                Provenance::new(p, 1),
                ev(),
            )
            .unwrap()
            .id()
        };
        let main = Claim::IsFunction { entry: Va(0x1000) };
        assert_eq!(f(main.clone(), "a"), f(main.clone(), "a"));
        assert_ne!(f(main.clone(), "a"), f(main.clone(), "b"));
        assert_ne!(f(main, "a"), f(Claim::NoReturn { entry: Va(0x1000) }, "a"));
        // Length prefixes keep ("ab", pass "c") apart from ("a", pass "bc").
        let n = |s: &str| Claim::Name {
            entity: Va(1),
            name: s.into(),
        };
        assert_ne!(f(n("ab"), "c"), f(n("a"), "bc"));
        // The id is part of the on-disk format: it must never change.
        assert_eq!(
            f(
                Claim::IsFunction {
                    entry: Va(0x401000)
                },
                "seeds.entry"
            )
            .to_string(),
            "836307b50e621432bdbdba501ba973f3"
        );
    }

    #[test]
    fn invalid_facts_are_refused() {
        let p = || Provenance::new("p", 1);
        let half = Confidence::new(0.5).unwrap();
        let mk = |c, s, conf, e| Fact::new(c, s, conf, p(), e);
        let code = |a, b| Claim::IsCode {
            start: Va(a),
            end: Va(b),
        };
        assert_eq!(
            mk(code(4, 4), Status::Inferred, half, ev()).unwrap_err(),
            FactError::EmptyRange
        );
        assert_eq!(
            mk(code(4, 8), Status::Inferred, half, vec![]).unwrap_err(),
            FactError::NoEvidence
        );
        assert_eq!(
            mk(code(4, 8), Status::User, half, ev()).unwrap_err(),
            FactError::NotCertain(Status::User)
        );
        let name = |s: &str| Claim::Name {
            entity: Va(1),
            name: s.into(),
        };
        assert_eq!(
            mk(name(""), Status::Declared, half, ev()).unwrap_err(),
            FactError::BadName
        );
        assert_eq!(
            mk(name("a\nb"), Status::Declared, half, ev()).unwrap_err(),
            FactError::BadName
        );
        assert_eq!(
            Fact::new(
                code(4, 8),
                Status::Inferred,
                half,
                Provenance::new("", 1),
                ev()
            )
            .unwrap_err(),
            FactError::NoPass
        );
        assert!(mk(code(4, 8), Status::Declared, half, ev()).is_ok());
    }
}
