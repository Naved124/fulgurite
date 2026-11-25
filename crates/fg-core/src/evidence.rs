// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Evidence: the human-readable, clickable reason behind a verdict.
//!
//! In later milestones this is the `evidence` list of a Fact (see the design
//! document, section 4.2). It lives in `fg-core` so every crate shares one type.

use crate::span::Span;
use serde::{Deserialize, Serialize};

/// One reason supporting a conclusion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Evidence {
    /// What was observed, in plain words.
    pub text: String,
    /// The bytes that were observed, when the evidence comes from the file.
    pub span: Option<Span>,
}

impl Evidence {
    /// Evidence without a file location.
    pub fn new(text: impl Into<String>) -> Evidence {
        Evidence {
            text: text.into(),
            span: None,
        }
    }

    /// Evidence pointing at specific bytes.
    pub fn at(text: impl Into<String>, span: Span) -> Evidence {
        Evidence {
            text: text.into(),
            span: Some(span),
        }
    }
}
