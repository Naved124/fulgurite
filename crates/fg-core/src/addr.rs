// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Address newtypes. A virtual address and a file offset are both `u64`, but
//! mixing them up is one of the most common loader bugs, so they are distinct types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A virtual address in the program's address space.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Va(pub u64);

/// A byte offset from the start of the input file.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct FileOffset(pub u64);

impl Va {
    /// Adds `delta`, returning `None` on overflow instead of wrapping.
    pub fn checked_add(self, delta: u64) -> Option<Va> {
        self.0.checked_add(delta).map(Va)
    }
}

impl FileOffset {
    /// Adds `delta`, returning `None` on overflow instead of wrapping.
    pub fn checked_add(self, delta: u64) -> Option<FileOffset> {
        self.0.checked_add(delta).map(FileOffset)
    }
}

impl fmt::Display for Va {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for FileOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_hex() {
        assert_eq!(Va(0x401000).to_string(), "0x401000");
        assert_eq!(FileOffset(0x40).to_string(), "0x40");
    }

    #[test]
    fn checked_add_detects_overflow() {
        assert_eq!(Va(u64::MAX).checked_add(1), None);
        assert_eq!(FileOffset(1).checked_add(2), Some(FileOffset(3)));
    }
}
