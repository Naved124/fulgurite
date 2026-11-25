// SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
// SPDX-License-Identifier: Apache-2.0

//! Provenance down to the byte: every parsed value can remember exactly which
//! bytes of the input file it was read from.

use crate::addr::FileOffset;
use serde::{Deserialize, Serialize};

/// A half-open range of file bytes `[offset, offset + len)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// First byte of the range.
    pub offset: FileOffset,
    /// Number of bytes in the range.
    pub len: u64,
}

impl Span {
    /// Creates a span starting at `offset` covering `len` bytes.
    pub fn new(offset: u64, len: u64) -> Span {
        Span {
            offset: FileOffset(offset),
            len,
        }
    }

    /// Offset of the last byte in the span (`offset + len - 1`), or `None` for an
    /// empty span. This is the inclusive end used when displaying ranges.
    pub fn last(&self) -> Option<FileOffset> {
        if self.len == 0 {
            None
        } else {
            self.offset.checked_add(self.len - 1)
        }
    }

    /// Exclusive end offset (`offset + len`), or `None` on overflow.
    pub fn end(&self) -> Option<FileOffset> {
        self.offset.checked_add(self.len)
    }
}

/// A parsed value together with the bytes it was read from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Field<T> {
    /// The decoded value.
    pub value: T,
    /// Where in the file the value came from.
    pub span: Span,
}

impl<T> Field<T> {
    /// Pairs a value with its source span.
    pub fn new(value: T, span: Span) -> Field<T> {
        Field { value, span }
    }

    /// Transforms the value while keeping its provenance.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Field<U> {
        Field {
            value: f(self.value),
            span: self.span,
        }
    }
}

impl<T: Copy> Field<T> {
    /// Returns the value (convenience for `Copy` types).
    pub fn get(&self) -> T {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_is_inclusive_end() {
        let s = Span::new(0x40, 8);
        assert_eq!(s.last(), Some(FileOffset(0x47)));
        assert_eq!(s.end(), Some(FileOffset(0x48)));
        assert_eq!(Span::new(0, 0).last(), None);
    }

    #[test]
    fn map_keeps_span() {
        let f = Field::new(3u16, Span::new(0x10, 2)).map(u32::from);
        assert_eq!(f.value, 3u32);
        assert_eq!(f.span, Span::new(0x10, 2));
    }
}
