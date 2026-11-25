// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

use fg_core::Anomaly;
use std::fmt;

/// Why a file could not be loaded at all.
///
/// Recoverable problems are reported as anomalies on a successful load; this
/// error is only for inputs where no useful model can be built.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// The magic number does not match any supported format.
    NotRecognized {
        /// The first bytes of the file (up to 4).
        magic: Vec<u8>,
    },
    /// The file is recognised but too damaged to model.
    Malformed {
        /// One-line summary.
        reason: String,
        /// Everything found before giving up.
        anomalies: Vec<Anomaly>,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::NotRecognized { magic } => {
                write!(f, "unrecognised file format (first bytes:")?;
                for b in magic {
                    write!(f, " {b:02x}")?;
                }
                write!(f, ")")
            }
            LoadError::Malformed { reason, .. } => write!(f, "malformed file: {reason}"),
        }
    }
}

impl std::error::Error for LoadError {}
