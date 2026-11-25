// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Fulgurite's analysis passes. Each pass reads the loaded file (and facts other
//! passes made) and produces facts with evidence; nothing here keeps results
//! outside the fact store but projections of it (the CFG, cross-references),
//! which are re-derived from the accepted facts.

pub mod cfg;
pub mod seeds;
pub mod track;
pub mod xrefs;
