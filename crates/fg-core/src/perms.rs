//! Memory permissions.

use serde::Serialize;
use std::fmt;

/// Read / write / execute permissions of a memory region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Perms {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

impl Perms {
    /// Builds permissions from three flags.
    pub fn new(read: bool, write: bool, execute: bool) -> Perms {
        Perms {
            read,
            write,
            execute,
        }
    }

    /// Writable and executable at the same time: a classic red flag.
    pub fn is_wx(self) -> bool {
        self.write && self.execute
    }
}

impl fmt::Display for Perms {
    /// Formats as `RWX`, with `-` for a missing permission (e.g. `R-X`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = |on: bool, ch: char| if on { ch } else { '-' };
        write!(
            f,
            "{}{}{}",
            c(self.read, 'R'),
            c(self.write, 'W'),
            c(self.execute, 'X')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(Perms::new(true, false, true).to_string(), "R-X");
        assert_eq!(Perms::new(true, true, false).to_string(), "RW-");
        assert!(Perms::new(true, true, true).is_wx());
    }
}
