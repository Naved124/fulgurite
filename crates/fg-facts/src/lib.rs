//! Fulgurite's fact model.
//!
//! Everything the analysis concludes is a [`Fact`]: a [`Claim`] about the
//! program with a [`Status`] (who said it), a [`Confidence`] (how sure), a
//! [`Provenance`] (which pass, from which other facts) and evidence (why). The
//! functions, blocks and edges other crates show are projections of the facts
//! that the [`FactStore`] accepts under the resolution rules, so a human can
//! always ask "why?" and get an answer that leads back to bytes in the file.
//!
//! The rules are the design document's sections 4.2 to 4.5 and 12.1 to 12.2.

pub mod confidence;
pub mod fact;
pub mod store;

pub use confidence::{Bucket, Confidence};
pub use fact::{
    Claim, EdgeKind, EvidenceKind, Fact, FactError, FactId, Provenance, Slot, Status, Support,
};
pub use store::{FactStore, Inserted, OpSeq, Resolution, StoreError, TIE, Verdict, Warning};
