//! Anomalies: places where the input is malformed, unusual or deliberately
//! misleading. Loaders report them instead of failing, because malware relies
//! on exactly these quirks.

use crate::span::Span;
use serde::Serialize;

/// How serious an anomaly is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    /// Unusual but harmless.
    Info,
    /// Violates a specification or common practice; analysis continues.
    Warning,
    /// Part of the input could not be interpreted.
    Error,
}

/// One problem found in the input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Anomaly {
    /// How serious it is.
    pub severity: Severity,
    /// Stable machine-readable identifier, e.g. `elf.phdr.table_truncated`.
    pub code: &'static str,
    /// Human-readable explanation.
    pub message: String,
    /// The bytes involved, when known.
    pub span: Option<Span>,
    /// What a real operating-system loader does with this input, when known.
    pub os_behaviour: Option<String>,
}

impl Anomaly {
    /// Creates an anomaly with no location.
    pub fn new(severity: Severity, code: &'static str, message: impl Into<String>) -> Anomaly {
        Anomaly {
            severity,
            code,
            message: message.into(),
            span: None,
            os_behaviour: None,
        }
    }

    /// Attaches the offending bytes.
    pub fn at(mut self, span: Span) -> Anomaly {
        self.span = Some(span);
        self
    }

    /// Attaches a note on how a real OS loader behaves.
    pub fn os(mut self, behaviour: impl Into<String>) -> Anomaly {
        self.os_behaviour = Some(behaviour.into());
        self
    }
}
