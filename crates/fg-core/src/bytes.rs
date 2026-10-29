//! Bounds-checked access to untrusted bytes.
//!
//! Every read of input data in Fulgurite goes through [`ByteView`]. Offsets and
//! lengths come from the file being analysed and may be hostile, so all
//! arithmetic is checked and every read returns a `Result` instead of panicking.

use crate::span::{Field, Span};
use serde::Serialize;
use std::fmt;

/// Byte order of multi-byte integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Endian {
    /// Least significant byte first (x86-64, most AArch64 systems).
    Little,
    /// Most significant byte first.
    Big,
}

/// A read that would go past the end of the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OutOfBounds {
    /// Requested start offset.
    pub offset: u64,
    /// Requested length.
    pub len: u64,
    /// Total bytes available.
    pub available: u64,
}

impl fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "read of {} byte(s) at offset {:#x} is outside the data ({} bytes)",
            self.len, self.offset, self.available
        )
    }
}

impl std::error::Error for OutOfBounds {}

/// An immutable, bounds-checked view over input bytes with a fixed byte order.
#[derive(Clone, Copy, Debug)]
pub struct ByteView<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> ByteView<'a> {
    /// Wraps `data`, interpreting multi-byte integers with `endian`.
    pub fn new(data: &'a [u8], endian: Endian) -> ByteView<'a> {
        ByteView { data, endian }
    }

    /// Same bytes, different byte order.
    pub fn with_endian(self, endian: Endian) -> ByteView<'a> {
        ByteView {
            data: self.data,
            endian,
        }
    }

    /// Byte order used by the integer readers.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Total number of bytes.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// True if there are no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// True if `[offset, offset + len)` lies entirely inside the data.
    pub fn contains(&self, offset: u64, len: u64) -> bool {
        offset.checked_add(len).is_some_and(|end| end <= self.len())
    }

    /// Returns the bytes `[offset, offset + len)`.
    pub fn bytes(&self, offset: u64, len: u64) -> Result<&'a [u8], OutOfBounds> {
        let oob = OutOfBounds {
            offset,
            len,
            available: self.len(),
        };
        let end = offset.checked_add(len).ok_or(oob)?;
        if end > self.len() {
            return Err(oob);
        }
        // Both values are <= data.len(), which fits in usize.
        Ok(&self.data[offset as usize..end as usize])
    }

    /// Returns all bytes from `offset` to the end of the data.
    pub fn tail(&self, offset: u64) -> Result<&'a [u8], OutOfBounds> {
        let len = self.len().checked_sub(offset).ok_or(OutOfBounds {
            offset,
            len: 0,
            available: self.len(),
        })?;
        self.bytes(offset, len)
    }

    /// Reads an unsigned integer of `size` bytes (1, 2, 4 or 8) at `offset`.
    ///
    /// # Panics
    /// Panics if `size` is not 1, 2, 4 or 8: that is a programming error in the
    /// caller, never a property of the input.
    pub fn uint(&self, offset: u64, size: u8) -> Result<u64, OutOfBounds> {
        assert!(
            matches!(size, 1 | 2 | 4 | 8),
            "unsupported integer size {size}"
        );
        let raw = self.bytes(offset, u64::from(size))?;
        let mut buf = [0u8; 8];
        let value = match self.endian {
            Endian::Little => {
                buf[..raw.len()].copy_from_slice(raw);
                u64::from_le_bytes(buf)
            }
            Endian::Big => {
                buf[8 - raw.len()..].copy_from_slice(raw);
                u64::from_be_bytes(buf)
            }
        };
        Ok(value)
    }

    /// Reads one byte.
    pub fn u8(&self, offset: u64) -> Result<u8, OutOfBounds> {
        self.uint(offset, 1).map(|v| v as u8)
    }

    /// Reads a 16-bit unsigned integer.
    pub fn u16(&self, offset: u64) -> Result<u16, OutOfBounds> {
        self.uint(offset, 2).map(|v| v as u16)
    }

    /// Reads a 32-bit unsigned integer.
    pub fn u32(&self, offset: u64) -> Result<u32, OutOfBounds> {
        self.uint(offset, 4).map(|v| v as u32)
    }

    /// Reads a 64-bit unsigned integer.
    pub fn u64(&self, offset: u64) -> Result<u64, OutOfBounds> {
        self.uint(offset, 8)
    }

    /// Reads an unsigned integer of `size` bytes and records where it came from.
    pub fn field_uint(&self, offset: u64, size: u8) -> Result<Field<u64>, OutOfBounds> {
        let value = self.uint(offset, size)?;
        Ok(Field::new(value, Span::new(offset, u64::from(size))))
    }

    /// Reads one byte with provenance.
    pub fn field_u8(&self, offset: u64) -> Result<Field<u8>, OutOfBounds> {
        Ok(self.field_uint(offset, 1)?.map(|v| v as u8))
    }

    /// Reads a 16-bit integer with provenance.
    pub fn field_u16(&self, offset: u64) -> Result<Field<u16>, OutOfBounds> {
        Ok(self.field_uint(offset, 2)?.map(|v| v as u16))
    }

    /// Reads a 32-bit integer with provenance.
    pub fn field_u32(&self, offset: u64) -> Result<Field<u32>, OutOfBounds> {
        Ok(self.field_uint(offset, 4)?.map(|v| v as u32))
    }

    /// Reads a 64-bit integer with provenance.
    pub fn field_u64(&self, offset: u64) -> Result<Field<u64>, OutOfBounds> {
        self.field_uint(offset, 8)
    }

    /// Reads a NUL-terminated byte string starting at `offset`, looking at most
    /// `max_len` bytes ahead. The returned span covers the string **without** the
    /// terminator. Returns `None` if no terminator is found within the limit.
    pub fn cstr(&self, offset: u64, max_len: u64) -> Result<Option<Field<&'a [u8]>>, OutOfBounds> {
        let rest = self.tail(offset)?;
        let window = &rest[..rest
            .len()
            .min(usize::try_from(max_len).unwrap_or(usize::MAX))];
        Ok(window
            .iter()
            .position(|&b| b == 0)
            .map(|n| Field::new(&window[..n], Span::new(offset, n as u64))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    #[test]
    fn little_and_big_endian() {
        let le = ByteView::new(&DATA, Endian::Little);
        let be = le.with_endian(Endian::Big);
        assert_eq!(le.u16(0).unwrap(), 0x0201);
        assert_eq!(be.u16(0).unwrap(), 0x0102);
        assert_eq!(le.u32(4).unwrap(), 0x0807_0605);
        assert_eq!(be.u64(0).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn reads_past_end_fail() {
        let v = ByteView::new(&DATA, Endian::Little);
        assert!(v.u64(1).is_err());
        assert!(v.u8(8).is_err());
        let e = v.u32(6).unwrap_err();
        assert_eq!(
            e,
            OutOfBounds {
                offset: 6,
                len: 4,
                available: 8
            }
        );
    }

    #[test]
    fn offset_overflow_does_not_wrap() {
        let v = ByteView::new(&DATA, Endian::Little);
        assert!(v.bytes(u64::MAX, 2).is_err());
        assert!(!v.contains(u64::MAX - 1, 4));
        assert!(v.tail(9).is_err());
    }

    #[test]
    fn field_records_span() {
        let v = ByteView::new(&DATA, Endian::Little);
        let f = v.field_u16(2).unwrap();
        assert_eq!(f.value, 0x0403);
        assert_eq!(f.span, Span::new(2, 2));
    }

    #[test]
    fn cstr_respects_limit() {
        let data = b"abc\0def";
        let v = ByteView::new(data, Endian::Little);
        let s = v.cstr(0, 16).unwrap().unwrap();
        assert_eq!(s.value, b"abc");
        assert_eq!(s.span, Span::new(0, 3));
        assert!(
            v.cstr(4, 16).unwrap().is_none(),
            "no terminator after 'def'"
        );
        assert!(
            v.cstr(0, 2).unwrap().is_none(),
            "terminator beyond the limit"
        );
    }
}
